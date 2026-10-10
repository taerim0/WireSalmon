import { en } from './en.ts';
import { ko, type Messages } from './ko.ts';

export type { Messages };

/** 언어를 추가하려면 ko.ts와 같은 모양의 파일을 만들고 여기에 등록한다 */
export const LOCALES = { ko, en } satisfies Record<string, Messages>;
export type Locale = keyof typeof LOCALES;

export const LOCALE_NAMES: Record<Locale, string> = { ko: '한국어', en: 'English' };

export const isLocale = (value: unknown): value is Locale => typeof value === 'string' && value in LOCALES;
