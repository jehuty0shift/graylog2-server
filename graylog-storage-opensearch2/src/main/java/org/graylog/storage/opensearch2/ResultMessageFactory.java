package org.graylog.storage.opensearch2;

import org.opensearch.common.text.Text;
import org.opensearch.search.SearchHit;
import org.opensearch.search.fetch.subphase.highlight.HighlightField;
import org.graylog2.indexer.results.ResultMessage;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ResultMessageFactory {
    public static ResultMessage fromSearchHit(SearchHit hit) {
        final Map<String, List<String>> highlights = hit.getHighlightFields().entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, ResultMessageFactory::highlightsFromFragments));
        return ResultMessage.parseFromSource(hit.getId(), hit.getIndex(), hit.getSourceAsMap(), highlights);
    }

    private static List<String> highlightsFromFragments(Map.Entry<String, HighlightField> entry) {
        return Arrays.stream(entry.getValue().fragments())
                .map(Text::toString)
                .collect(Collectors.toList());
    }
}
