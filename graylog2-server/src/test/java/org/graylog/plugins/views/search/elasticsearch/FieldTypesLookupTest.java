/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.views.search.elasticsearch;

import com.google.common.collect.ImmutableSet;
import org.graylog2.indexer.fieldtypes.FieldTypeDTO;
import org.graylog2.indexer.fieldtypes.IndexFieldTypesDTO;
import org.graylog2.indexer.fieldtypes.IndexFieldTypesService;
import org.graylog2.indexer.fieldtypes.MappedFieldTypesService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FieldTypesLookupTest {
    private MappedFieldTypesService mappedFieldTypesService;
    private FieldTypesLookup fieldTypesLookup;

    @BeforeEach
    void setUp() {
        this.mappedFieldTypesService = mock(MappedFieldTypesService.class);
        this.fieldTypesLookup = new FieldTypesLookup(mappedFieldTypesService);
    }

//    @Test
//    void returnsEmptyOptionalIfFieldTypesAreEmpty() {
//        final Optional<String> result = this.fieldTypesLookup.getType(Collections.singleton("SomeStream"), "somefield");
//        assertThat(result).isEmpty();
//    }
//
//    @Test
//    void returnsEmptyOptionalIfStreamsAreEmpty() {
//        final Optional<String> result = this.fieldTypesLookup.getType(Collections.emptySet(), "somefield");
//        assertThat(result).isEmpty();
//    }
//
//    @Test
//    void returnsEmptyOptionalIfMultipleTypesExistForField() {
//        when(this.mappedFieldTypesService.physicalTypeByStreamIds(Collections.singleton("stream1"), Mockito.any())).thenReturn(
//                ImmutableSet.of(
//                        FieldTypeDTO.create("somefield", "long"),
//                        FieldTypeDTO.create("somefield", "float")
//                ));
//
//        final Optional<String> result = this.fieldTypesLookup.getType(Collections.singleton("stream1"), "somefield");
//        assertThat(result).isEmpty();
//    }
//
//    @Test
//    void returnsEmptyOptionalIfNoTypesExistForStream() {
//        when(this.mappedFieldTypesService.physicalTypeByStreamIds(Collections.singleton("stream2"), Mockito.anyString())).thenReturn(Collections.emptySet());
//
//        final Optional<String> result = this.fieldTypesLookup.getType(Collections.singleton("stream2"), "somefield");
//        assertThat(result).isEmpty();
//    }
//
//    @Test
//    void returnsFieldTypeIfSingleTypeExistsForFieldInStream() {
//        when(this.mappedFieldTypesService.physicalTypeByStreamIds(Collections.singleton("stream1"), Mockito.anyString())).thenReturn(
//                ImmutableSet.of(FieldTypeDTO.create("somefield", "long")));
//
//        final Optional<String> result = this.fieldTypesLookup.getType(Collections.singleton("stream1"), "somefield");
//        assertThat(result).contains("long");
//    }
//
//    @Test
//    void returnsFieldTypeIfSingleTypeExistsForFieldInAllStreams() {
//        when(this.mappedFieldTypesService.physicalTypeByStreamIds(ImmutableSet.of("stream1", "stream2"), Mockito.anyString())).thenReturn(
//                ImmutableSet.of(
//                        FieldTypeDTO.create("somefield", "long")
//                ));
//
//        final Optional<String> result = this.fieldTypesLookup.getType(ImmutableSet.of("stream1", "stream2"), "somefield");
//        assertThat(result).contains("long");
//    }
}
