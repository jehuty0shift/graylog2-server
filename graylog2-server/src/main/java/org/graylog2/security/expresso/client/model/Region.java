package org.graylog2.security.expresso.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum Region {
    @JsonProperty("EU")
    EU,

    @JsonProperty("CA")
    CA;
}
