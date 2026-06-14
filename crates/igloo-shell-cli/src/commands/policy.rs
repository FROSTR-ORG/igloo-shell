use super::super::*;

pub fn policy_direction(value: CliPolicyDirection) -> PolicyDirection {
    match value {
        CliPolicyDirection::Request => PolicyDirection::Request,
        CliPolicyDirection::Respond => PolicyDirection::Respond,
    }
}

pub fn policy_method(value: CliPolicyMethod) -> PolicyMethod {
    match value {
        CliPolicyMethod::Ping => PolicyMethod::Ping,
        CliPolicyMethod::Onboard => PolicyMethod::Onboard,
        CliPolicyMethod::Sign => PolicyMethod::Sign,
        CliPolicyMethod::Ecdh => PolicyMethod::Ecdh,
    }
}

pub fn policy_value(value: CliPolicyValue) -> PolicyOverrideValue {
    match value {
        CliPolicyValue::Unset => PolicyOverrideValue::Unset,
        CliPolicyValue::Allow => PolicyOverrideValue::Allow,
        CliPolicyValue::Deny => PolicyOverrideValue::Deny,
        CliPolicyValue::Ask => PolicyOverrideValue::Ask,
    }
}
