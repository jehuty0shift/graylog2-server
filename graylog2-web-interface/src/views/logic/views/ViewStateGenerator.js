// @flow strict
import * as Immutable from 'immutable';

import View from './View';
import ViewState from './ViewState';
import type { ViewType } from './View';

import { resultHistogram, allMessagesTable } from '../Widgets';
import WidgetPosition from '../widgets/WidgetPosition';


type Result = {
  titles: { widget: { [string]: string } },
  widgets: Array<Widget>,
  positions: { [string]: WidgetPosition },
};

const _defaultWidgets: { [ViewType]: (?string) => Promise<Result> } = {
  [View.Type.Search]: async (streamId: ?string) => {
    const histogram = resultHistogram();
    const messageTable = allMessagesTable(undefined, []);
    const widgets = [
      histogram,
      messageTable,
    ];

    const titles = {
      widget: {
        [histogram.id]: 'Message Count',
        [messageTable.id]: 'All Messages',
      },
    };

    const positions = {
      [histogram.id]: new WidgetPosition(1, 1, 2, Infinity),
      [messageTable.id]: new WidgetPosition(1, 3, 6, Infinity),
    };

    return { titles, widgets, positions };
  },
  // eslint-disable-next-line no-unused-vars
  [View.Type.Dashboard]: async (streamId: ?string) => {
    const widgets = [];
    const titles = {};
    const positions = {};

    return { titles, widgets, positions };
  },
};

export default async (type: ViewType, streamId: ?string) => {
  const { titles, widgets, positions } = await _defaultWidgets[type](streamId);

  return ViewState.create()
    .toBuilder()
    .titles(titles)
    .widgets(Immutable.List(widgets))
    .widgetPositions(positions)
    .build();
};
