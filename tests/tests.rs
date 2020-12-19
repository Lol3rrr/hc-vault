mod approle {
    mod auth;
    mod is_expired;
}

mod database {
    mod get_credentials;
}

mod general {
    mod reauth;
    mod vault_request;
}

mod kubernetes {
    mod auth;
    mod is_expired;
}

mod kv2 {
    mod configure;
    mod delete;
    mod delete_metadata_all_versions;
    mod delete_versions;
    mod destroy_versions;
    mod get;
    mod get_configuration;
    mod undelete_versions;
    mod update_set;
}
