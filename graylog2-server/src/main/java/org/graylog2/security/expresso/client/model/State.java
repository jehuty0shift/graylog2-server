package org.graylog2.security.expresso.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum State {

    @JsonProperty("expired")
    EXPIRED,
    @JsonProperty("inCreation")
    IN_CREATION,
    @JsonProperty("ok")
    OK,
    @JsonProperty("suspended")
    SUSPENDED;

}
