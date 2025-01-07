// @flow strict
import * as React from 'react';
import { render, screen } from '@testing-library/react';
import { AdditionalContext } from 'views/logic/ActionContext';

import SelectExtractorType from './SelectExtractorType';

import FieldType from '../fieldtypes/FieldType';

describe('SelectExtractorType', () => {
  const value = 'value of message';
  const field = 'value_field';
  const focus = jest.fn();

  window.open = jest.fn(() => { return { focus }; });

  const message = {
    fields: {
      gl2_source_input: 'input-id',
      gl2_source_node: 'node-id',
    },
    formattedFields: {},
    id: 'message-id',
    index: 'message-index',
  };

  it('should render', () => {
    render(
      <AdditionalContext.Provider key="message-key" value={{ message }}>
        <SelectExtractorType onClose={() => {}} value={value} field={field} queryId="foo" type={FieldType.Unknown} />
      </AdditionalContext.Provider>,
    );
    const bootstrapModalForm = wrapper.find('BootstrapModalForm');

    expect(bootstrapModalForm).toExist();
    expect(bootstrapModalForm).toHaveProp('show', true);
  });

  it('should select a extractor and open a new window', async () => {
    render(
      <AdditionalContext.Provider value={{ message }}>
        <SelectExtractorType
          onClose={() => {}}
          value={value}
          field={field}
          queryId="foo"
          type={FieldType.Unknown}
        />
      </AdditionalContext.Provider>
    );

    // Find the select element by its placeholder text
    const select = screen.getByPlaceholderText('Select extractor type');

    // Simulate user selecting an option
    await userEvent.selectOptions(select, 'grok');

    // Find the form element
    const form = screen.getByRole('form');

    // Submit the form
    fireEvent.submit(form);

    // Assert that window.open was called
    expect(window.open).toHaveBeenCalled();
    // Assert that focus was called on the new window
    expect(window.open().focus).toHaveBeenCalled();
  });
});
