package org.graylog2.shared.security;

public interface Auditable {
    default boolean mustAudit(){return true;}
}
