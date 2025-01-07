import React from 'react';
import PropTypes from 'prop-types';
import styled, { withTheme } from 'styled-components';

import { Label } from 'components/graylog';

const ColorLabelWrap = styled.span(({ size, theme }) => {
  const { body, small, tiny } = theme.fonts.size;
  const fontSize = size === 'small' ? small : body;

  return `
    vertical-align: middle;
    font-size: ${size === 'xsmall' ? tiny : fontSize};
  `;
});

const ColorLabel = ({ color, size, text, theme }) => {
  const borderColor = theme.utils.colorLevel(color, 5); //backgroundColor.darker();
  const textColor = theme.utils.contrastingColor(color);

  return (
    <ColorLabelWrap size={size}>
      <Label style={{
        backgroundColor: color,
        border: `1px solid ${borderColor}`,
        color: textColor,
      }}>
        {text}
      </Label>
    </ColorLabelWrap>
  );
};

ColorLabel.propTypes = {
  color: PropTypes.string.isRequired,
  text: PropTypes.oneOfType([PropTypes.string, PropTypes.element]),
  size: PropTypes.oneOf(['normal', 'small', 'xsmall']),
  theme: PropTypes.shape({
    colors: PropTypes.object,
  }).isRequired,
};

ColorLabel.defaultProps = {
  text: <span>&emsp;</span>,
  size: 'normal',
};

export default withTheme(ColorLabel);
