use anyhow::Result;

use super::{BoxError, CorrelationStore, Label, Point, Row};
use std::sync::Arc;

use tsink::{DataPoint, Label as TSinkLabel, Row as TSinkRow, Storage, StorageBuilder, TimestampPrecision};

pub struct TSinkStore {
    storage: Arc<dyn Storage>,
}

impl Default for TSinkStore {
    fn default() -> Self {
        Self {
            storage: StorageBuilder::default()
                .build()
                .expect("failed to build tsink memory storage"),
        }
    }
}

impl Into<TSinkLabel> for Label {
    fn into(self) -> TSinkLabel {
        TSinkLabel::new(self.name, self.value)
    }
}

impl Into<TSinkLabel> for &Label {
    fn into(self) -> TSinkLabel {
        TSinkLabel::new(self.name.clone(), self.value.clone())
    }
}

impl Into<Label> for &TSinkLabel {
    fn into(self) -> Label {
        Label::new(self.name.clone(), self.value.clone())
    }
}

impl Into<TSinkRow> for Row {
    fn into(self) -> TSinkRow {
        let dp = DataPoint::new(self.point.timestamp, self.point.value);
        if self.labels.is_empty() {
            TSinkRow::new(self.metric.clone(), dp)
        } else {
            let labels = self
                .labels
                .into_iter()
                .map(|l| l.into())
                .collect::<Vec<_>>();
            TSinkRow::with_labels(self.metric.clone(), labels, dp)
        }
    }
}

impl Into<TSinkRow> for &Row {
    fn into(self) -> TSinkRow {
        let dp = DataPoint::new(self.point.timestamp, self.point.value);
        if self.labels.is_empty() {
            TSinkRow::new(self.metric.clone(), dp)
        } else {
            let labels = self.labels.iter().map(|l| l.into()).collect::<Vec<_>>();
            TSinkRow::with_labels(self.metric.clone(), labels, dp)
        }
    }
}

impl Into<Point> for DataPoint {
    fn into(self) -> Point {
        Point::new(self.timestamp, self.value)
    }
}

impl CorrelationStore for TSinkStore {
    fn new() -> Result<Self, BoxError> {
        let storage = StorageBuilder::new().build()?;

        Ok(Self { storage })
    }

    fn new_with_expiry(expire: std::time::Duration) -> Result<Self, BoxError> {
        // miliseconds precision: seconds are too coarse for temporal ordering
        // default nanosecond precision is a waste of memory
        let storage = StorageBuilder::new()
        .with_retention(expire)
        .with_timestamp_precision(TimestampPrecision::Milliseconds)
        .build()?;

        Ok(Self { storage })
    }

    fn insert_rows(&self, rows: &[Row]) -> Result<(), BoxError> {
        let tsink_rows: Vec<TSinkRow> = rows.iter().map(|r| r.into()).collect();

        self.storage
            .insert_rows(&tsink_rows)
            .map_err(|e| -> BoxError { Box::new(e) })?;

        Ok(())
    }

    fn select(
        &self,
        metric: &str,
        labels: &[Label],
        start: i64,
        end: i64,
    ) -> Result<Vec<Point>, BoxError> {
        let tsink_labels = labels.iter().map(|l| l.into()).collect::<Vec<_>>();

        let pts = self
            .storage
            .select(metric, &tsink_labels, start, end)
            .map(|p| p.into_iter().map(|dp| dp.into()).collect::<Vec<Point>>())
            .map_err(|e| -> BoxError { Box::new(e) })?;

        Ok(pts)
    }

    fn select_all(
        &self,
        metric: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<(Vec<Label>, Vec<Point>)>, BoxError> {
        let series = self
            .storage
            .select_all(metric, start, end)
            .map_err(|e| -> BoxError { Box::new(e) })?;

        Ok(series
            .into_iter()
            .map(|(labels, pts)| {
                let labels = labels.iter().map(|l| l.into()).collect::<Vec<_>>();

                let pts = pts.into_iter().map(|p| p.into()).collect::<Vec<_>>();
                (labels, pts)
            })
            .collect())
    }
}
