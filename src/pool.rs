#[cfg(feature = "async")]
use crate::transport::{AsyncRealRpcTransport, RealTransportConfig, TransportError};
#[cfg(feature = "async")]
use deadpool::managed::{Manager, Object, Pool, RecycleError, RecycleResult};
#[cfg(feature = "async")]
use deadpool_runtime::Runtime;
#[cfg(feature = "async")]
use std::sync::Arc;
#[cfg(feature = "async")]
use std::time::Duration;
#[cfg(feature = "async")]
use thiserror::Error;
#[cfg(feature = "async")]
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[cfg(feature = "async")]
#[derive(Clone)]
pub struct AsyncTransportManager {
    config: RealTransportConfig,
}

#[cfg(feature = "async")]
impl AsyncTransportManager {
    pub fn new(config: RealTransportConfig) -> Self {
        Self { config }
    }
}

#[cfg(feature = "async")]
impl Manager for AsyncTransportManager {
    type Type = AsyncRealRpcTransport;
    type Error = TransportError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        AsyncRealRpcTransport::connect(self.config.clone()).await
    }

    async fn recycle(&self, conn: &mut Self::Type, _metrics: &deadpool::managed::Metrics) -> RecycleResult<Self::Error> {
        conn.check()
            .await
            .map_err(|err| RecycleError::Message(err.to_string().into()))
    }
}

#[cfg(feature = "async")]
#[derive(Clone)]
pub struct GenericConnectionPool<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    pool: Pool<M>,
    semaphore: Arc<Semaphore>,
}

#[cfg(feature = "async")]
pub struct GenericConnectionPoolBuilder<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    manager: M,
    max_size: usize,
    min_idle: usize,
    wait_timeout: Duration,
    concurrency_limit: Option<usize>,
}

#[cfg(feature = "async")]
impl<M> GenericConnectionPoolBuilder<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    pub fn new(manager: M) -> Self {
        Self {
            manager,
            max_size: 500,
            min_idle: 50,
            wait_timeout: Duration::from_secs(30),
            concurrency_limit: None,
        }
    }

    pub fn max_size(&mut self, max_size: usize) -> &mut Self {
        self.max_size = max_size;
        self
    }

    pub fn min_idle(&mut self, min_idle: usize) -> &mut Self {
        self.min_idle = min_idle;
        self
    }

    pub fn wait_timeout(&mut self, wait_timeout: Duration) -> &mut Self {
        self.wait_timeout = wait_timeout;
        self
    }

    pub fn concurrency_limit(&mut self, limit: usize) -> &mut Self {
        self.concurrency_limit = Some(limit.max(1));
        self
    }

    pub fn build(self) -> Result<GenericConnectionPool<M>, PoolBuildError> {
        let pool = Pool::builder(self.manager)
            .max_size(self.max_size)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(PoolBuildError::Pool)?;

        let limit = self
            .concurrency_limit
            .or_else(concurrency_from_env)
            .unwrap_or(100);

        Ok(GenericConnectionPool {
            pool,
            semaphore: Arc::new(Semaphore::new(limit)),
        })
    }
}

#[cfg(feature = "async")]
impl<M> GenericConnectionPool<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    pub async fn acquire(&self) -> Result<GenericPooledTransport<M>, PoolAcquireError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PoolAcquireError::Closed)?;

        let connection = self.pool.get().await
            .map_err(|_| PoolAcquireError::Pool(deadpool::managed::PoolError::Closed))?;

        Ok(GenericPooledTransport {
            inner: connection,
            _permit: permit,
        })
    }
}

#[cfg(feature = "async")]
fn concurrency_from_env() -> Option<usize> {
    std::env::var("WMI_CONCURRENCY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
}

#[cfg(feature = "async")]
pub struct GenericPooledTransport<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    inner: Object<M>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(feature = "async")]
impl<M> std::ops::Deref for GenericPooledTransport<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    type Target = M::Type;

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

#[cfg(feature = "async")]
impl<M> std::ops::DerefMut for GenericPooledTransport<M>
where
    M: Manager + Clone + Send + Sync + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}

#[cfg(feature = "async")]
#[derive(Clone)]
pub struct WmiConnectionPool {
    inner: GenericConnectionPool<AsyncTransportManager>,
}

#[cfg(feature = "async")]
pub struct WmiConnectionPoolBuilder {
    inner: GenericConnectionPoolBuilder<AsyncTransportManager>,
}

#[cfg(feature = "async")]
impl WmiConnectionPoolBuilder {
    pub fn new(config: RealTransportConfig) -> Self {
        Self {
            inner: GenericConnectionPoolBuilder::new(AsyncTransportManager::new(config)),
        }
    }

    pub fn builder(config: RealTransportConfig) -> Self {
        Self::new(config)
    }

    pub fn max_size(mut self, max_size: usize) -> Self {
        self.inner.max_size(max_size);
        self
    }

    pub fn min_idle(mut self, min_idle: usize) -> Self {
        self.inner.min_idle(min_idle);
        self
    }

    pub fn wait_timeout(mut self, wait_timeout: Duration) -> Self {
        self.inner.wait_timeout(wait_timeout);
        self
    }

    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.inner.concurrency_limit(limit);
        self
    }

    pub fn build(self) -> Result<WmiConnectionPool, PoolBuildError> {
        let inner = self.inner.build()?;
        Ok(WmiConnectionPool { inner })
    }
}

#[cfg(feature = "async")]
impl WmiConnectionPool {
    pub fn builder(config: RealTransportConfig) -> WmiConnectionPoolBuilder {
        WmiConnectionPoolBuilder::builder(config)
    }

    pub async fn acquire(&self) -> Result<PooledTransport, PoolAcquireError> {
        self.inner
            .acquire()
            .await
            .map(|inner| PooledTransport { inner })
    }
}

#[cfg(feature = "async")]
pub struct PooledTransport {
    inner: GenericPooledTransport<AsyncTransportManager>,
}

#[cfg(feature = "async")]
impl std::ops::Deref for PooledTransport {
    type Target = AsyncRealRpcTransport;

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

#[cfg(feature = "async")]
impl std::ops::DerefMut for PooledTransport {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}

#[cfg(feature = "async")]
#[derive(Debug, Error)]
pub enum PoolBuildError {
    #[error("failed to build connection pool: {0}")]
    Pool(deadpool::managed::BuildError),
}

#[cfg(feature = "async")]
#[derive(Debug, Error)]
pub enum PoolAcquireError {
    #[error("pool acquisition failed: {0}")]
    Pool(#[from] deadpool::managed::PoolError<TransportError>),
    #[error("concurrency guard closed")]
    Closed,
}

#[cfg(all(test, feature = "async"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct DummyManager {
        counter: Arc<AtomicUsize>,
    }

    struct DummyTransport {
        id: usize,
    }

    impl Manager for DummyManager {
        type Type = DummyTransport;
        type Error = TransportError;

        async fn create(&self) -> Result<Self::Type, Self::Error> {
            let id = self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(DummyTransport { id })
        }

        async fn recycle(&self, _conn: &mut Self::Type, _metrics: &deadpool::managed::Metrics) -> RecycleResult<Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn checkout_and_return_connection() {
        let manager = DummyManager {
            counter: Arc::new(AtomicUsize::new(0)),
        };

        let mut builder = GenericConnectionPoolBuilder::new(manager.clone());
        builder.concurrency_limit(2);
        let pool = builder.build().expect("build pool");

        let conn = pool.acquire().await.expect("acquire connection");
        let first_id = conn.id;
        drop(conn);

        let next = pool.acquire().await.expect("acquire again");
        // Pool may reuse the same connection or create a new one
        assert!(next.id == first_id || next.id == first_id + 1);
    }
}
