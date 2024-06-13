import PropTypes from 'prop-types';
import React from 'react';

import { MenuItem, NavDropdown } from 'components/graylog';
import { ExternalLink, Icon } from 'components/common';
import DocsHelper from 'util/DocsHelper';

import AppConfig from 'util/AppConfig'

const HelpMenu = ({ active }) => (
  <NavDropdown active={active}
               id="help-menu-dropdown"
               title={<Icon name="question-circle" size="lg" />}
               aria-label="Help"
               noCaret>

    <MenuItem href={AppConfig.webUIGuideLink()} target="_blank">
      <ExternalLink>Getting Started</ExternalLink>
    </MenuItem>

    <MenuItem href={AppConfig.webUICommunityLink()} target="_blank">
      <ExternalLink>Community</ExternalLink>
    </MenuItem>
  </NavDropdown>
);

HelpMenu.propTypes = {
  active: PropTypes.bool.isRequired,
};

export default HelpMenu;
