import { createContext, useContext } from 'react';
import { isLocale, LOCALES, type Locale, type Messages } from '../i18n/index.ts';

const STORAGE_KEY = 'wiresalmon.locale';

/** 저장해 둔 선택이 있으면 그것을, 없으면 브라우저 언어를 따른다 */
export function initialLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (isLocale(saved)) return saved;
  } catch {
    // 저장소를 쓸 수 없는 환경에서는 브라우저 언어만 본다
  }
  return navigator.language.toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

export function saveLocale(locale: Locale) {
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    // 저장하지 못해도 이번 화면에서는 그대로 동작한다
  }
}

export const LocaleContext = createContext<Messages>(LOCALES.ko);
export const useMessages = () => useContext(LocaleContext);
