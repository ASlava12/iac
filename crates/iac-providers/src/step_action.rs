//! Phase 7cz.20: per-provider `StepAction` enums.
//!
//! Pre-7cz every provider matched on `step.action.as_str()` against
//! literals like `"file.write"` / `"docker.pull"`. Typos compiled fine
//! and only blew up at runtime with an "unknown step action" error.
//! The protocol's `Step.action: String` stays as the wire format
//! (operations are serialised to disk and across the wire), but every
//! provider now declares its action namespace as an enum so:
//!
//! * `apply()` matches the parsed enum exhaustively — adding a new
//!   variant without handling it is a compile error.
//! * `plan()` constructs steps from `Variant.as_str()`, so a renamed
//!   action stays consistent in plan/apply/audit at compile time.
//! * Typos in tests / fixture YAML are caught the same way: if a
//!   string doesn't parse to a known variant, the provider's
//!   `StepAction::parse()` returns a structured error before the
//!   executor invokes `apply()`.
//!
//! Usage:
//! ```ignore
//! step_actions!(FileAction {
//!     Write  => "file.write",
//!     Delete => "file.delete",
//! });
//! ```
//! Generates `enum FileAction { Write, Delete }` plus `as_str()` and
//! `parse()` methods returning `iac_core::Error::provider(...)` on
//! unknown input.

#[macro_export]
macro_rules! step_actions {
    ($name:ident { $( $variant:ident => $str:literal ),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $name {
            $( $variant ),+
        }

        impl $name {
            #[inline]
            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $str ),+
                }
            }

            #[inline]
            pub(crate) fn parse(s: &str) -> ::std::result::Result<Self, ::iac_core::Error> {
                match s {
                    $( $str => ::std::result::Result::Ok(Self::$variant), )+
                    other => ::std::result::Result::Err(
                        ::iac_core::Error::provider(
                            stringify!($name),
                            format!("unknown step action {other:?}"),
                        ),
                    ),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    // Smoke-test the macro itself. Every provider's enum is tested
    // separately via its own apply/plan tests.
    step_actions!(SmokeAction {
        Foo => "smoke.foo",
        Bar => "smoke.bar",
    });

    #[test]
    fn round_trip() {
        assert_eq!(SmokeAction::Foo.as_str(), "smoke.foo");
        assert_eq!(SmokeAction::Bar.as_str(), "smoke.bar");
        assert!(matches!(SmokeAction::parse("smoke.foo"), Ok(SmokeAction::Foo)));
        assert!(matches!(SmokeAction::parse("smoke.bar"), Ok(SmokeAction::Bar)));
        assert!(SmokeAction::parse("smoke.unknown").is_err());
        assert_eq!(format!("{}", SmokeAction::Foo), "smoke.foo");
    }
}
