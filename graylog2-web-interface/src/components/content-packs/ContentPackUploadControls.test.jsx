import React from 'react';
import { mount } from 'wrappedEnzyme';
import { render, screen } from '@testing-library/react';
import 'helpers/mocking/react-dom_mock';

import ContentPackUploadControls from 'components/content-packs/ContentPackUploadControls';

describe('<ContentPackUploadControls />', () => {
  it('should render', () => {
    const wrapper = mount(<ContentPackUploadControls />);

    expect(wrapper).toExist();
  });
});
