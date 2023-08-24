use num_traits::FromPrimitive;

/// BGP Role
///
/// Defined in [RFC9234](https://www.iana.org/go/rfc9234).
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpRole {
    Provider = 0,
    RouteServer = 1,
    RouteServerClient = 2,
    Customer = 3,
    Peer = 4,
}

pub fn parse_bgp_role_value(value: &u8) -> Option<BgpRole> {
    BgpRole::from_u8(*value)
}

/// Validate the local-remote BGP Role pairs.
///
/// This function checks the role correctness by following the description in [Section 4.2 of RFC9234](https://www.rfc-editor.org/rfc/rfc9234.html#section-4.2).
///
/// The acceptable local-remote BGP pairs are:
///
/// Local AS Role | Remote AS Role
/// --- | ---
/// Provider | Customer
/// Customer | Provider
/// RouteServer | RouterServer-Client
/// RouterServer-Client | RouteServer
/// Peer | Peer
///
pub fn validate_role_pairs(local_role: &BgpRole, remote_role: &BgpRole) -> bool {
    match local_role {
        BgpRole::Provider => {
            if let BgpRole::Customer = remote_role {
                return true;
            }
            false
        }
        BgpRole::RouteServer => {
            if let BgpRole::RouteServerClient = remote_role {
                return true;
            }
            false
        }
        BgpRole::RouteServerClient => {
            if let BgpRole::RouteServer = remote_role {
                return true;
            }
            false
        }
        BgpRole::Customer => {
            if let BgpRole::Provider = remote_role {
                return true;
            }
            false
        }
        BgpRole::Peer => {
            if let BgpRole::Peer = remote_role {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::BgpRole::*;

    #[test]
    fn test_bgp_role_validation() {
        let mut local: BgpRole;
        let mut remote: BgpRole;

        local = Provider;
        remote = Customer;
        assert_eq!(validate_role_pairs(&local, &remote), true);
        for remote in [Provider, Peer, RouteServer, RouteServerClient] {
            assert_eq!(validate_role_pairs(&local, &remote), false);
        }

        local = Customer;
        remote = Provider;
        assert_eq!(validate_role_pairs(&local, &remote), true);
        for remote in [Customer, Peer, RouteServer, RouteServerClient] {
            assert_eq!(validate_role_pairs(&local, &remote), false);
        }

        local = RouteServer;
        remote = RouteServerClient;
        assert_eq!(validate_role_pairs(&local, &remote), true);
        for remote in [Provider, Customer, Peer, RouteServer] {
            assert_eq!(validate_role_pairs(&local, &remote), false);
        }

        local = RouteServerClient;
        remote = RouteServer;
        assert_eq!(validate_role_pairs(&local, &remote), true);
        for remote in [Provider, Customer, Peer, RouteServerClient] {
            assert_eq!(validate_role_pairs(&local, &remote), false);
        }

        local = Peer;
        remote = Peer;
        assert_eq!(validate_role_pairs(&local, &remote), true);
        for remote in [Provider, Customer, RouteServer, RouteServerClient] {
            assert_eq!(validate_role_pairs(&local, &remote), false);
        }
    }
}
