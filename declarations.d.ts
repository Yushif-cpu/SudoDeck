// Ambient declarations for Next.js, React and Supabase when opened in IDE without full Next.js node_modules
declare module 'react' {
  const React: any;
  export default React;
  export const useState: any;
  export const useEffect: any;
  export const useMemo: any;
  export const useCallback: any;
  export const useRef: any;
}

declare module 'react/jsx-runtime' {
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
}

declare module 'next/server' {
  export class NextRequest {
    cookies: any;
    headers: any;
    json(): Promise<any>;
    nextUrl: { searchParams: URLSearchParams };
  }
  export class NextResponse {
    cookies: any;
    static json(body: any, init?: any): any;
    static next(options?: any): any;
  }
}

declare module 'next/headers' {
  export function cookies(): Promise<any>;
}

declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
  interface Element extends Record<string, any> {}
}
