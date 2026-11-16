use daimon_host::{
    AuthenticatedSessionV1,
    presence::{AgentId, Disclosure, Observation, ReadError, Roster},
};
use std::time::{Duration, Instant};

struct Policy(bool);

impl Disclosure for Policy {
    fn allows_roster(&mut self, _: &AuthenticatedSessionV1) -> bool {
        self.0
    }

    fn allows_agent(&mut self, _: &AuthenticatedSessionV1, agent: AgentId) -> bool {
        agent != [2; 16]
    }
}

#[test]
fn reports_only_visible_observations_and_distinguishes_unavailable_from_empty() {
    let session = AuthenticatedSessionV1 {
        principal: [9; 16],
        authority_context: [8; 16],
    };
    let now = Instant::now();
    let freshness = Duration::from_secs(1);
    let mut roster = Roster::new(3, freshness);
    assert!(matches!(
        roster.read(&session, &mut Policy(false), now, 1),
        Err(ReadError::Denied)
    ));
    assert!(matches!(
        roster.read(&session, &mut Policy(true), now, 1),
        Err(ReadError::Unavailable)
    ));
    assert!(roster.replace([([1; 16], now - freshness), ([2; 16], now)]));
    let page = roster.read(&session, &mut Policy(true), now, 1).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].agent, [1; 16]);
    assert_eq!(
        page.entries[0].observation,
        Observation::Stale { age: freshness }
    );
    assert!(!page.truncated);

    assert!(roster.replace([([1; 16], now), ([2; 16], now), ([3; 16], now)]));
    let page = roster.read(&session, &mut Policy(true), now, 1).unwrap();
    assert!(page.truncated);
    assert_eq!(
        page.entries[0].observation,
        Observation::Observed {
            age: Duration::ZERO
        }
    );

    assert!(!roster.replace([([1; 16], now); 2]));
    assert!(matches!(
        roster.read(&session, &mut Policy(true), now, 1),
        Err(ReadError::Unavailable)
    ));
    assert!(roster.replace([]));
    assert!(
        roster
            .read(&session, &mut Policy(true), now, 1)
            .unwrap()
            .entries
            .is_empty()
    );
}
