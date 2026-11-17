-- Security gate caps for every severity, not only critical and high
-- (NULL = no limit, like the existing caps).
ALTER TABLE gate_policies
    ADD COLUMN max_medium INT CHECK (max_medium >= 0),
    ADD COLUMN max_low    INT CHECK (max_low >= 0),
    ADD COLUMN max_info   INT CHECK (max_info >= 0);
