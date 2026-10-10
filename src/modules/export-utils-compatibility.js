// ExportUtilsCompatibility owns legacy browser globals for VSDX helper access.

import * as ExportUtils from './export-utils.js';

const root = typeof window !== 'undefined' ? window : null;

if (root) {
  root.resolveColor = ExportUtils.resolveColor;
  root._sanitizeName = ExportUtils.sanitizeName;

  let vsdxCache = null;
  Object.defineProperty(root, '_vsdx', {
    get() {
      if (!vsdxCache) {
        vsdxCache = {
          resetShapeState: ExportUtils.resetShapeState,
          getShapes: ExportUtils.getShapes,
          getPolyEdges: ExportUtils.getPolyEdges,
          getIdMap: ExportUtils.getIdMap,
          setIdMapEntry: ExportUtils.setIdMapEntry,
          xmlEsc: ExportUtils.xmlEsc,
          uid: ExportUtils.uid,
          addRect: ExportUtils.addRect,
          addPolyEdge: ExportUtils.addPolyEdge,
          buildSubText: ExportUtils.buildSubText,
          buildShape: ExportUtils.buildShape,
          buildPolyConnector: ExportUtils.buildPolyConnector,
          buildVsdxXml: ExportUtils.buildVsdxXml,
          computeSubnetHeights: ExportUtils.computeSubnetHeights,
          computePageDimensions: ExportUtils.computePageDimensions,
          gwStyles: ExportUtils.gwStyles,
          PX: ExportUtils.PX,
          SUB_W: ExportUtils.SUB_W,
          SUB_H_MIN: ExportUtils.SUB_H_MIN,
          SUB_GAP: ExportUtils.SUB_GAP,
          VNET_PAD: ExportUtils.VNET_PAD,
          VNET_HDR: ExportUtils.VNET_HDR,
          GW_INSIDE_W: ExportUtils.GW_INSIDE_W,
          GW_INSIDE_H: ExportUtils.GW_INSIDE_H,
          GW_INSIDE_GAP: ExportUtils.GW_INSIDE_GAP,
          GW_ROW_H: ExportUtils.GW_ROW_H,
          COL_GAP: ExportUtils.COL_GAP,
          LINE_H: ExportUtils.LINE_H,
          TOP_MARGIN: ExportUtils.TOP_MARGIN,
          toIn: ExportUtils.toIn
        };
      }
      return vsdxCache;
    },
    configurable: true
  });
}
