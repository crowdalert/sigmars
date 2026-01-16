use std::error::Error;
use std::time::Duration;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct Label {
    pub name: String,
    pub value: String,
}
impl Label {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Point {
    pub timestamp: i64,
    pub value: f64,
}
impl Point {
    pub fn new(timestamp: i64, value: f64) -> Self {
        Self { timestamp, value }
    }
}

#[derive(Debug, Clone)]
pub struct Row {
    pub metric: String,
    pub labels: Vec<Label>,
    pub point: Point,
}

impl Row {
    pub fn new(metric: impl Into<String>, point: Point) -> Self {
        Self {
            metric: metric.into(),
            labels: Vec::new(),
            point,
        }
    }

    pub fn with_labels(metric: impl Into<String>, labels: Vec<Label>, point: Point) -> Self {
        Self {
            metric: metric.into(),
            labels,
            point,
        }
    }
}

/// Backend interface (plugin boundary).
///
/// Minimal operations needed by the correlation engine:
/// - write time series points
/// - read points for a specific label set
/// - enumerate all label sets for a metric (needed for value_count)
pub trait CorrelationStore: Send + Sync {
    fn new() -> Result<Self, BoxError>
    where
        Self: Sized;

    /// Create a new store with the given retention duration.
    /// Default implementation calls `new()`, ignoring the retention parameter.
    fn new_with_expiry(_: Duration) -> Result<Self, BoxError>
    where
        Self: Sized,
    {
        Self::new()
    }

    fn insert_rows(&self, rows: &[Row]) -> Result<(), BoxError>;

    fn select(
        &self,
        metric: &str,
        labels: &[Label],
        start: i64,
        end: i64,
    ) -> Result<Vec<Point>, BoxError>;

    fn select_all(
        &self,
        metric: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<(Vec<Label>, Vec<Point>)>, BoxError>;
}

pub struct CorrelationStoreNOP {}

impl CorrelationStore for CorrelationStoreNOP {
    fn new() -> Result<Self, BoxError>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn insert_rows(&self, _: &[Row]) -> Result<(), BoxError> {
        Ok(())
    }

    fn select(&self, _: &str, _: &[Label], _: i64, _: i64) -> Result<Vec<Point>, BoxError> {
        Ok(Vec::new())
    }

    fn select_all(
        &self,
        _: &str,
        _: i64,
        _: i64,
    ) -> Result<Vec<(Vec<Label>, Vec<Point>)>, BoxError> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "tsink")]
pub mod tsink;
