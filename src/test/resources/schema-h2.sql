create schema if not exists pwa;
create schema if not exists jwt_blacklist;
create schema if not exists jwt_whitelist;

create table if not exists pwa.sessions (
    sess_id bigint not null,
    session_id varchar,
    ssl_session_id varchar,
    personal_code varchar,
    valid_from timestamp,
    valid_to timestamp,
    givenname varchar,
    surname varchar,
    channel varchar(30),
    ip varchar,
    params varchar,
    rights varchar,
    roles varchar,
    created timestamp,
    last_modified timestamp,
    username varchar(11),
    browser varchar,
    loginlevel varchar,
    xtee_asutus varchar,
    personal_fcode varchar,
    mobile_number varchar,
    cas_session_id varchar,
    certificate_type varchar
);

create schema if not exists asutused;

create alias if not exists asutused.check_rights as '
String checkRights(String value) {
    return "AMETNIK=KODANIK=0=0,ASUTUS=ASUTUS_ADMIN=14222=10347101,GENERAL=ARENDUS=14222=10347101,AMETNIK=ASUTUS=14222=10347101";
}';

create alias if not exists pwa.bg_login as '
String bg_login(String sessionId, String personalCode, String constantType) {
    return "";
}';

