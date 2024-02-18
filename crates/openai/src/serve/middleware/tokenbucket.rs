use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::homedir::home_dir;
use crate::{context, debug, error, now_duration};

pub trait TokenBucket: Send + Sync {
    fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Mem,
    ReDB,
}

impl Default for Strategy {
    fn default() -> Self {
        Self::Mem
    }
}

impl std::str::FromStr for Strategy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mem" => Ok(Strategy::Mem),
            "redb" => Ok(Strategy::ReDB),
            _ => anyhow::bail!("storage policy: {} is not supported", s),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct BucketState {
    tokens: u32,
    last_time: u64,
}

pub struct MemTokenBucket {
    enable: bool,
    /// token bucket capacity `capacity`
    capacity: u32,
    /// token bucket fill rate `fill_rate`
    fill_rate: u32,
    /// ip -> token backet
    buckets: moka::sync::Cache<IpAddr, BucketState>,
}

impl MemTokenBucket {
    pub fn new(enable: bool, capacity: u32, fill_rate: u32, expired: u32) -> Self {
        let buckets: Cache<IpAddr, BucketState> = Cache::builder()
            .max_capacity(65535)
            .time_to_idle(Duration::from_secs(expired as u64))
            .build();
        Self {
            enable,
            capacity,
            fill_rate,
            buckets,
        }
    }
}

impl TokenBucket for MemTokenBucket {
    fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        if !self.enable {
            return Ok(true);
        }

        let now_timestamp = now_duration()?.as_secs();

        let mut bucket = self
            .buckets
            .entry(ip)
            .or_insert(BucketState {
                tokens: self.capacity,
                last_time: now_timestamp,
            })
            .into_value();

        let elapsed = now_timestamp - bucket.last_time;
        let tokens_to_add = (elapsed as u32) * self.fill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.capacity);
        bucket.last_time = now_timestamp;

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            self.buckets.insert(ip, bucket);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

use anyhow::Result;
use native_db::*;
use native_model::{native_model, Model};

static DATABASE_BUILDER: OnceLock<DatabaseBuilder> = OnceLock::new();

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[native_model(id = 1, version = 1)]
#[native_db]
struct ReDBBucketState {
    #[primary_key]
    ip: u128,
    tokens: u32,
    last_time: u64,
}

#[derive(typed_builder::TypedBuilder)]
pub struct RedisTokenBucket<'a> {
    enable: bool,
    /// token bucket capacity `capacity`
    capacity: u32,
    /// token bucket fill rate `fill_rate`
    fill_rate: u32,
    /// native db
    db: Arc<native_db::Database<'a>>,
}

impl<'a> RedisTokenBucket<'a> {
    pub fn new(enable: bool, capacity: u32, fill_rate: u32, expired: u32) -> Self {
        // create database
        let builder = DATABASE_BUILDER.get_or_init(|| {
            let mut builder = DatabaseBuilder::new();
            builder
                .define::<ReDBBucketState>()
                .expect("define table failed");
            builder
        });

        let db = builder
            .create(
                home_dir()
                    .expect("Failed to get home directory")
                    .join(context::WORKER_DIR)
                    .join("token_bucket.db"),
            )
            .expect("create database failed");
        let db = Arc::new(db);
        // clear expired buckets every expired seconds
        clear_expired_buckets_every(db.clone(), expired);
        Self {
            enable,
            capacity,
            fill_rate,
            db,
        }
    }
}

fn clear_expired_buckets_every(db: Arc<Database<'static>>, expired: u32) {
    use std::thread;
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(expired.into()));

        debug!("ReDB Clearing expired buckets...");

        let r = match db.r_transaction() {
            Ok(r) => r,
            Err(e) => {
                error!("Error starting read transaction: {}", e);
                continue;
            }
        };

        let now_timestamp = match now_duration() {
            Ok(t) => t.as_secs(),
            Err(e) => {
                error!("Error getting current time: {}", e);
                continue;
            }
        };

        let scan = match r.scan().primary::<ReDBBucketState>() {
            Ok(scan) => scan,
            Err(e) => {
                error!("Error starting scan: {}", e);
                continue;
            }
        };

        for bucket in scan.all() {
            if now_timestamp - bucket.last_time >= expired.into() {
                let rw = match db.rw_transaction() {
                    Ok(rw) => rw,
                    Err(e) => {
                        error!("Error starting read-write transaction: {}", e);
                        continue;
                    }
                };

                if let Err(e) = rw.remove(bucket) {
                    error!("Error removing bucket: {}", e);
                }

                if let Err(e) = rw.commit() {
                    error!("Error committing transaction: {}", e);
                }
            }
        }
    });
}

impl TokenBucket for RedisTokenBucket<'_> {
    fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        if !self.enable {
            return Ok(true);
        }

        let rw = self.db.rw_transaction()?;
        let pk = ip_to_number(ip);
        let now_timestamp = now_duration()?.as_secs();
        let mut bucket: ReDBBucketState = match rw.get().primary(pk)? {
            Some(bucket) => bucket,
            None => ReDBBucketState {
                ip: pk,
                tokens: self.capacity,
                last_time: now_timestamp,
            },
        };

        let elapsed = now_timestamp - bucket.last_time;
        let tokens_to_add = (elapsed as u32) * self.fill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.capacity);
        bucket.last_time = now_timestamp;

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            rw.insert(bucket)?;
            rw.commit()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn ip_to_number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            ((octets[0] as u128) << 24)
                + ((octets[1] as u128) << 16)
                + ((octets[2] as u128) << 8)
                + (octets[3] as u128)
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            ((octets[0] as u128) << 120)
                + ((octets[1] as u128) << 112)
                + ((octets[2] as u128) << 104)
                + ((octets[3] as u128) << 96)
                + ((octets[4] as u128) << 88)
                + ((octets[5] as u128) << 80)
                + ((octets[6] as u128) << 72)
                + ((octets[7] as u128) << 64)
                + ((octets[8] as u128) << 56)
                + ((octets[9] as u128) << 48)
                + ((octets[10] as u128) << 40)
                + ((octets[11] as u128) << 32)
                + ((octets[12] as u128) << 24)
                + ((octets[13] as u128) << 16)
                + ((octets[14] as u128) << 8)
                + (octets[15] as u128)
        }
    }
}

pub enum TokenBucketProvider {
    Mem(MemTokenBucket),
    ReDB(RedisTokenBucket<'static>),
}

impl From<(Strategy, bool, u32, u32, u32)> for TokenBucketProvider {
    fn from(value: (Strategy, bool, u32, u32, u32)) -> Self {
        let strategy = match value.0 {
            Strategy::Mem => Self::Mem(MemTokenBucket::new(value.1, value.2, value.3, value.4)),
            Strategy::ReDB => Self::ReDB(RedisTokenBucket::new(value.1, value.2, value.3, value.4)),
        };
        strategy
    }
}

impl TokenBucket for TokenBucketProvider {
    fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        let condition = match self {
            Self::Mem(t) => t.acquire(ip),
            Self::ReDB(t) => t.acquire(ip),
        };
        Ok(condition?)
    }
}
