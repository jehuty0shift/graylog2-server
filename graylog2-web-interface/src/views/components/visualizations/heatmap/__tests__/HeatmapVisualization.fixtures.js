const validData = [
  {
    key: ['00'],
    values: [
      { key: ['100', 'count()'], value: 217, rollup: false, source: 'col-leaf' },
      { key: ['304', 'count()'], value: 213, rollup: false, source: 'col-leaf' },
      { key: ['203', 'count()'], value: 206, rollup: false, source: 'col-leaf' },
      { key: ['204', 'count()'], value: 195, rollup: false, source: 'col-leaf' },
      { key: ['count()'], value: 4140, rollup: true, source: 'row-leaf' },
    ],
    source: 'leaf',
  },
  {
    key: ['01'],
    values: [
      { key: ['405', 'count()'], value: 230, rollup: false, source: 'col-leaf' },
      { key: ['201', 'count()'], value: 217, rollup: false, source: 'col-leaf' },
      { key: ['500', 'count()'], value: 215, rollup: false, source: 'col-leaf' },
      { key: ['406', 'count()'], value: 205, rollup: false, source: 'col-leaf' },
      { key: ['count()'], value: 4140, rollup: true, source: 'row-leaf' },
    ],
    source: 'leaf',
  },
  {
    key: ['02'],
    values: [
      { key: ['416', 'count()'], value: 218, rollup: false, source: 'col-leaf' },
      { key: ['203', 'count()'], value: 210, rollup: false, source: 'col-leaf' },
      { key: ['201', 'count()'], value: 203, rollup: false, source: 'col-leaf' },
      { key: ['503', 'count()'], value: 202, rollup: false, source: 'col-leaf' },
      { key: ['count()'], value: 4140, rollup: true, source: 'row-leaf' },
    ],
    source: 'leaf',
  },
  {
    key: ['03'],
    values: [
      { key: ['400', 'count()'], value: 244, rollup: false, source: 'col-leaf' },
      { key: ['205', 'count()'], value: 221, rollup: false, source: 'col-leaf' },
      { key: ['401', 'count()'], value: 220, rollup: false, source: 'col-leaf' },
      { key: ['200', 'count()'], value: 212, rollup: false, source: 'col-leaf' },
      { key: ['count()'], value: 4140, rollup: true, source: 'row-leaf' },
    ],
    source: 'leaf',
  },
  {
    key: ['04'],
    values: [
      { key: ['503', 'count()'], value: 227, rollup: false, source: 'col-leaf' },
      { key: ['203', 'count()'], value: 220, rollup: false, source: 'col-leaf' },
      { key: ['500', 'count()'], value: 220, rollup: false, source: 'col-leaf' },
      { key: ['201', 'count()'], value: 212, rollup: false, source: 'col-leaf' },
      { key: ['count()'], value: 4140, rollup: true, source: 'row-leaf' },
    ],
    source: 'leaf',
  },
  {
    key: [],
    values: [
      { key: ['count()'], value: 100000, rollup: true, source: 'row-inner' },
    ],
    source: 'non-leaf',
  },
];
// eslint-disable-next-line import/prefer-default-export
export { validData };
