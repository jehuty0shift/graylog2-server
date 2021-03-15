package org.graylog2.indexer.fieldtypes.kefla;

import java.time.Instant;
import java.util.*;

/**
 * Created by jehuty0shift on 17/09/19.
 */
public class KIndexMapping {

    private final String index;
    private String kId;
    private Map<String, Set<String>> streamFieldsMap;
    private Instant updateDate;

    public KIndexMapping(String index, String kId) {
        this.index = index;
        this.kId = kId;
        streamFieldsMap = new HashMap<>();
        updateDate = Instant.now();
    }


    public boolean addFieldsForStream(String streamId, Collection<String> fieldNames) {
        return streamFieldsMap.computeIfAbsent(streamId, k -> new HashSet<>(fieldNames.size())).addAll(fieldNames);
    }

    public String getkId() {
        return kId;
    }

    public Map<String, Set<String>> getStreamFieldsMap() {
        return streamFieldsMap;
    }

    public String getIndex() {
        return index;
    }

    public Instant getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(Instant updateDate) {
        this.updateDate = updateDate;
    }

    public boolean containsField(Collection<String> streamIds, String fieldName) {
        return streamIds.stream().anyMatch(s -> streamFieldsMap.getOrDefault(s, Collections.emptySet()).contains(fieldName));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KIndexMapping that = (KIndexMapping) o;
        return index.equals(that.index) && kId.equals(that.kId) && streamFieldsMap.equals(that.streamFieldsMap) && updateDate.equals(that.updateDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(index, kId, streamFieldsMap, updateDate);
    }

    @Override
    public String toString() {
        return "KIndexMapping{" +
                "index='" + index + '\'' +
                ", kId='" + kId + '\'' +
                ", streamFieldsMap=" + streamFieldsMap.size() +
                ", updateDate=" + updateDate +
                '}';
    }

}
