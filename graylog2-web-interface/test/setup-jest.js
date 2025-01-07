import jQuery from 'jquery';
import sizeMe from 'react-sizeme';
import '@testing-library/jest-dom';

import registerBuiltinStores from 'injection/registerBuiltinStores';

global.$ = jQuery;

global.jQuery = jQuery;

sizeMe.noPlaceholders = true;

registerBuiltinStores();
