/**
 * Format UTC date string from backend into client's local timezone
 */
export const formatLocalDateTime = (dateStr) => {
  if (!dateStr) return '';
  try {
    const normalized = typeof dateStr === 'string' && !dateStr.endsWith('Z') && !dateStr.includes('+')
      ? `${dateStr}Z`
      : dateStr;
    const date = new Date(normalized);
    if (isNaN(date.getTime())) return String(dateStr);
    return date.toLocaleString();
  } catch (e) {
    return String(dateStr);
  }
};

export const formatLocalTime = (dateStr) => {
  if (!dateStr) return '';
  try {
    const normalized = typeof dateStr === 'string' && !dateStr.endsWith('Z') && !dateStr.includes('+')
      ? `${dateStr}Z`
      : dateStr;
    const date = new Date(normalized);
    if (isNaN(date.getTime())) return String(dateStr);
    return date.toLocaleTimeString();
  } catch (e) {
    return String(dateStr);
  }
};
