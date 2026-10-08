//! A vector that cannot be empty.

use serde::{Deserialize, Serialize};

/// At least one element. Built only through [`NonEmpty::new`], so "a derivation with no
/// inputs" or "an extraction from no artefact" cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmpty<T: Clone>(Vec<T>);

/// The vector was empty.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("at least one element is required")]
pub struct Empty;

impl<T: Clone> NonEmpty<T> {
    /// These elements.
    ///
    /// # Errors
    /// `items` is empty.
    pub fn new(items: Vec<T>) -> Result<Self, Empty> {
        if items.is_empty() {
            Err(Empty)
        } else {
            Ok(Self(items))
        }
    }

    /// One element.
    pub fn one(item: T) -> Self {
        Self(vec![item])
    }

    /// The elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The number of elements, always at least one.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The same elements with `item` appended.
    #[must_use]
    pub fn push(mut self, item: T) -> Self {
        self.0.push(item);
        self
    }

    /// Always false; present so the type reads like a collection.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = Empty;

    fn try_from(v: Vec<T>) -> Result<Self, Empty> {
        Self::new(v)
    }
}

impl<T: Clone> From<NonEmpty<T>> for Vec<T> {
    fn from(n: NonEmpty<T>) -> Self {
        n.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_refused_in_code_and_in_json() {
        assert_eq!(NonEmpty::<u8>::new(vec![]), Err(Empty));
        assert!(serde_json::from_str::<NonEmpty<u8>>("[]").is_err());
        assert_eq!(
            serde_json::from_str::<NonEmpty<u8>>("[1,2]").unwrap().len(),
            2
        );
    }
}
