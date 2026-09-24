#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkPolicy {
    pub inbound_listener: bool,
    pub port_forwarding: bool,
    pub upnp: bool,
    pub nat_pmp: bool,
}

impl NetworkPolicy {
    pub const fn outbound_only(self) -> bool {
        !self.inbound_listener && !self.port_forwarding && !self.upnp && !self.nat_pmp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_preserves_phase_zero_network_invariant() {
        assert!(NetworkPolicy::default().outbound_only());
    }
}
