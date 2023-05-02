pub enum Endpoint {
    Register,
    AddAppointment,
    GetAppointment,
    GetSubscriptionInfo,
    Ping,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Endpoint::Register => "register",
                Endpoint::AddAppointment => "add_appointment",
                Endpoint::GetAppointment => "get_appointment",
                Endpoint::GetSubscriptionInfo => "get_subscription_info",
                Endpoint::Ping => "ping",
            }
        )
    }
}

impl Endpoint {
    pub fn path(&self) -> String {
        format!("/{self}")
    }
}
