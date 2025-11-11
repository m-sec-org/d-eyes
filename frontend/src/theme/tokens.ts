import type { ThemeConfig } from 'antd';
import { theme } from 'antd';

const palette = {
  primary: '#1774ff',
  primaryHover: '#3d89ff',
  primaryActive: '#125cd6',
  secondaryBorder: 'rgba(15, 23, 42, 0.12)',
  textPrimary: '#0b1a33',
  textSecondary: '#4b5565',
  borderRadius: 12,
  controlHeight: 40,
  success: '#52c41a',
  warning: '#faad14',
  danger: '#f5222d',
};

export const antdThemeConfig: ThemeConfig = {
  algorithm: theme.defaultAlgorithm,
  token: {
    colorPrimary: palette.primary,
    colorLink: palette.primary,
    colorBorder: palette.secondaryBorder,
    colorTextBase: palette.textPrimary,
    borderRadius: palette.borderRadius,
    fontSize: 14,
    controlHeight: palette.controlHeight,
    colorSuccess: palette.success,
    colorWarning: palette.warning,
    colorError: palette.danger,
  },
  components: {
    Button: {
      colorPrimary: palette.primary,
      colorPrimaryHover: palette.primaryHover,
      colorPrimaryActive: palette.primaryActive,
      borderRadius: palette.borderRadius,
      paddingInline: 20,
      paddingBlock: 10,
      controlHeight: palette.controlHeight,
      controlOutlineWidth: 2,
      controlOutline: 'rgba(23, 116, 255, 0.18)',
    },
    Input: {
      colorPrimary: palette.primary,
      borderRadius: palette.borderRadius,
      controlOutlineWidth: 2,
      activeShadow: '0 0 0 2px rgba(23, 116, 255, 0.15)',
      inputFontSize: 14,
    },
    Select: {
      borderRadius: palette.borderRadius,
      controlHeight: palette.controlHeight,
      colorBorder: palette.secondaryBorder,
      colorPrimary: palette.primary,
      controlOutline: 'rgba(23, 116, 255, 0.18)',
    },
    Segmented: {
      controlHeight: 36,
      itemSelectedBg: 'rgba(23, 116, 255, 0.12)',
      itemHoverBg: 'rgba(23, 116, 255, 0.08)',
      borderRadius: 999,
    },
    Card: {
      colorBorderSecondary: 'rgba(15, 23, 42, 0.04)',
      borderRadiusLG: 16,
      paddingLG: 20,
    },
    Table: {
      headerBg: '#f6f8fb',
      headerBorderRadius: 12,
      borderColor: 'rgba(15, 23, 42, 0.06)',
    },
    Tag: {
      borderRadiusSM: 999,
      paddingXS: 6,
    },
    Statistic: {
      contentFontSize: 26,
    },
  },
};
