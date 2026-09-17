// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Sherlock / Maigret OSINT Social Footprint Engine
// ══════════════════════════════════════════════════════════════════

import axios from 'axios';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

export const PLATFORMS = [
  // ── 1. Top Social & Messaging ──────────────────────────────────
  {
    name: 'GitHub',
    category: 'Developer',
    icon: 'github',
    url: 'https://github.com/{u}',
    checkUrl: 'https://api.github.com/users/{u}',
    type: 'api_status',
  },
  {
    name: 'Telegram',
    category: 'Messaging',
    icon: 'send',
    url: 'https://t.me/{u}',
    checkUrl: 'https://t.me/{u}',
    type: 'telegram_html',
  },
  {
    name: 'Reddit',
    category: 'Social',
    icon: 'message-square',
    url: 'https://www.reddit.com/user/{u}',
    checkUrl: 'https://www.reddit.com/user/{u}/about.json',
    type: 'reddit_api',
  },
  {
    name: 'Instagram',
    category: 'Social',
    icon: 'instagram',
    url: 'https://www.instagram.com/{u}/',
    checkUrl: 'https://www.instagram.com/{u}/',
    type: 'status_code',
  },
  {
    name: 'X (Twitter)',
    category: 'Social',
    icon: 'twitter',
    url: 'https://x.com/{u}',
    checkUrl: 'https://x.com/{u}',
    type: 'status_code',
  },
  {
    name: 'TikTok',
    category: 'Social',
    icon: 'video',
    url: 'https://www.tiktok.com/@{u}',
    checkUrl: 'https://www.tiktok.com/@{u}',
    type: 'status_code',
  },
  {
    name: 'YouTube',
    category: 'Media',
    icon: 'youtube',
    url: 'https://www.youtube.com/@{u}',
    checkUrl: 'https://www.youtube.com/@{u}',
    type: 'status_code',
  },
  {
    name: 'Pinterest',
    category: 'Social',
    icon: 'image',
    url: 'https://www.pinterest.com/{u}/',
    checkUrl: 'https://www.pinterest.com/{u}/',
    type: 'status_code',
  },
  {
    name: 'Threads',
    category: 'Social',
    icon: 'at-sign',
    url: 'https://www.threads.net/@{u}',
    checkUrl: 'https://www.threads.net/@{u}',
    type: 'status_code',
  },
  {
    name: 'VK (VKontakte)',
    category: 'Social',
    icon: 'share-2',
    url: 'https://vk.com/{u}',
    checkUrl: 'https://vk.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Mastodon',
    category: 'Social',
    icon: 'hash',
    url: 'https://mastodon.social/@{u}',
    checkUrl: 'https://mastodon.social/@{u}.json',
    type: 'api_status',
  },
  {
    name: 'Bluesky',
    category: 'Social',
    icon: 'cloud',
    url: 'https://bsky.app/profile/{u}.bsky.social',
    checkUrl: 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social',
    type: 'api_status',
  },

  // ── 2. Developer & Code Platforms ──────────────────────────────
  {
    name: 'GitLab',
    category: 'Developer',
    icon: 'git-branch',
    url: 'https://gitlab.com/{u}',
    checkUrl: 'https://gitlab.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Bitbucket',
    category: 'Developer',
    icon: 'git-commit',
    url: 'https://bitbucket.org/{u}/',
    checkUrl: 'https://api.bitbucket.org/2.0/users/{u}',
    type: 'api_status',
  },
  {
    name: 'DockerHub',
    category: 'Developer',
    icon: 'box',
    url: 'https://hub.docker.com/u/{u}',
    checkUrl: 'https://hub.docker.com/v2/users/{u}/',
    type: 'api_status',
  },
  {
    name: 'NPM',
    category: 'Developer',
    icon: 'package',
    url: 'https://www.npmjs.com/~{u}',
    checkUrl: 'https://www.npmjs.com/~{u}',
    type: 'status_code',
  },
  {
    name: 'PyPI',
    category: 'Developer',
    icon: 'code-2',
    url: 'https://pypi.org/user/{u}/',
    checkUrl: 'https://pypi.org/user/{u}/',
    type: 'status_code',
  },
  {
    name: 'Dev.to',
    category: 'Developer',
    icon: 'terminal',
    url: 'https://dev.to/{u}',
    checkUrl: 'https://dev.to/api/users/by_username?url={u}',
    type: 'api_status',
  },
  {
    name: 'HackerNews',
    category: 'Developer',
    icon: 'radio',
    url: 'https://news.ycombinator.com/user?id={u}',
    checkUrl: 'https://hacker-news.firebaseio.com/v0/user/{u}.json',
    type: 'hn_api',
  },
  {
    name: 'Codeforces',
    category: 'Developer',
    icon: 'award',
    url: 'https://codeforces.com/profile/{u}',
    checkUrl: 'https://codeforces.com/api/user.info?handles={u}',
    type: 'codeforces_api',
  },
  {
    name: 'Replit',
    category: 'Developer',
    icon: 'play',
    url: 'https://replit.com/@{u}',
    checkUrl: 'https://replit.com/@{u}',
    type: 'status_code',
  },
  {
    name: 'LeetCode',
    category: 'Developer',
    icon: 'cpu',
    url: 'https://leetcode.com/{u}/',
    checkUrl: 'https://leetcode.com/{u}/',
    type: 'status_code',
  },

  // ── 3. Media, Creative & Portfolio ─────────────────────────────
  {
    name: 'Medium',
    category: 'Media',
    icon: 'book-open',
    url: 'https://medium.com/@{u}',
    checkUrl: 'https://medium.com/@{u}',
    type: 'status_code',
  },
  {
    name: 'SoundCloud',
    category: 'Media',
    icon: 'music',
    url: 'https://soundcloud.com/{u}',
    checkUrl: 'https://soundcloud.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Spotify',
    category: 'Media',
    icon: 'disc',
    url: 'https://open.spotify.com/user/{u}',
    checkUrl: 'https://open.spotify.com/user/{u}',
    type: 'status_code',
  },
  {
    name: 'Behance',
    category: 'Media',
    icon: 'layout',
    url: 'https://www.behance.net/{u}',
    checkUrl: 'https://www.behance.net/{u}',
    type: 'status_code',
  },
  {
    name: 'Dribbble',
    category: 'Media',
    icon: 'dribbble',
    url: 'https://dribbble.com/{u}',
    checkUrl: 'https://dribbble.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Vimeo',
    category: 'Media',
    icon: 'film',
    url: 'https://vimeo.com/{u}',
    checkUrl: 'https://vimeo.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Flickr',
    category: 'Media',
    icon: 'camera',
    url: 'https://www.flickr.com/people/{u}',
    checkUrl: 'https://www.flickr.com/people/{u}',
    type: 'status_code',
  },
  {
    name: 'Twitch',
    category: 'Media',
    icon: 'tv',
    url: 'https://www.twitch.tv/{u}',
    checkUrl: 'https://www.twitch.tv/{u}',
    type: 'status_code',
  },

  // ── 4. Gaming & Community ──────────────────────────────────────
  {
    name: 'Steam',
    category: 'Gaming',
    icon: 'gamepad-2',
    url: 'https://steamcommunity.com/id/{u}',
    checkUrl: 'https://steamcommunity.com/id/{u}',
    type: 'steam_html',
  },
  {
    name: 'Chess.com',
    category: 'Gaming',
    icon: 'shield',
    url: 'https://www.chess.com/member/{u}',
    checkUrl: 'https://api.chess.com/pub/player/{u}',
    type: 'api_status',
  },
  {
    name: 'Lichess',
    category: 'Gaming',
    icon: 'crosshair',
    url: 'https://lichess.org/@/{u}',
    checkUrl: 'https://lichess.org/api/user/{u}',
    type: 'api_status',
  },
  {
    name: 'Linktree',
    category: 'Social',
    icon: 'link',
    url: 'https://linktr.ee/{u}',
    checkUrl: 'https://linktr.ee/{u}',
    type: 'status_code',
  },
  {
    name: 'Patreon',
    category: 'Social',
    icon: 'heart',
    url: 'https://www.patreon.com/{u}',
    checkUrl: 'https://www.patreon.com/{u}',
    type: 'status_code',
  },
  {
    name: 'Roblox',
    category: 'Gaming',
    icon: 'play-circle',
    url: 'https://www.roblox.com/user.aspx?username={u}',
    checkUrl: 'https://www.roblox.com/user.aspx?username={u}',
    type: 'status_code',
  },
];

export const PLATFORM_LOGOS = {
  'github': 'github',
  'telegram': 'telegram',
  'reddit': 'reddit',
  'instagram': 'instagram',
  'x (twitter)': 'x',
  'twitter': 'x',
  'x': 'x',
  'tiktok': 'tiktok',
  'youtube': 'youtube',
  'pinterest': 'pinterest',
  'threads': 'threads',
  'vk (vkontakte)': 'vk',
  'vk': 'vk',
  'mastodon': 'mastodon',
  'bluesky': 'bluesky',
  'gitlab': 'gitlab',
  'bitbucket': 'bitbucket',
  'dockerhub': 'docker',
  'docker': 'docker',
  'npm': 'npm',
  'pypi': 'pypi',
  'dev.to': 'devdotto',
  'hackernews': 'ycombinator',
  'codeforces': 'codeforces',
  'replit': 'replit',
  'leetcode': 'leetcode',
  'medium': 'medium',
  'soundcloud': 'soundcloud',
  'spotify': 'spotify',
  'behance': 'behance',
  'dribbble': 'dribbble',
  'vimeo': 'vimeo',
  'flickr': 'flickr',
  'twitch': 'twitch',
  'steam': 'steam',
  'chess.com': 'chessdotcom',
  'lichess': 'lichess',
  'linktree': 'linktree',
  'patreon': 'patreon',
  'roblox': 'roblox',
};

export function getPlatformLogo(name) {
  const key = (name || '').toLowerCase().trim();
  const slug = PLATFORM_LOGOS[key] || 'globe';
  return {
    slug,
    iconUrl: `/img/brands/${slug}.svg`,
  };
}

export async function checkSinglePlatform(platform, username) {
  const cleanUser = username.trim().toLowerCase();
  const profileUrl = platform.url.replace(/\{u\}/g, cleanUser);
  const checkUrl = platform.checkUrl.replace(/\{u\}/g, cleanUser);
  const startTime = Date.now();
  const { slug: logoSlug, iconUrl } = getPlatformLogo(platform.name);

  const client = axios.create({
    timeout: 4500,
    headers: {
      'User-Agent': USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    validateStatus: () => true, // Don't throw on 404
  });

  try {
    if (platform.type === 'api_status') {
      const res = await client.get(checkUrl);
      const exists = res.status === 200;
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    if (platform.type === 'reddit_api') {
      const res = await client.get(checkUrl);
      const exists = res.status === 200 && res.data && res.data.data && !res.data.data.is_suspended;
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    if (platform.type === 'hn_api') {
      const res = await client.get(checkUrl);
      const exists = res.status === 200 && res.data !== null && typeof res.data === 'object' && res.data.id;
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists: !!exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    if (platform.type === 'codeforces_api') {
      const res = await client.get(checkUrl);
      const exists = res.status === 200 && res.data && res.data.status === 'OK';
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    if (platform.type === 'telegram_html') {
      const res = await client.get(checkUrl);
      const html = typeof res.data === 'string' ? res.data : '';
      // Telegram shows tgme_page_extra or username in title when account exists
      const exists = res.status === 200 && (html.includes('tgme_page_extra') || html.includes('tgme_page_title')) && !html.includes('If you have Telegram, you can contact');
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    if (platform.type === 'steam_html') {
      const res = await client.get(checkUrl);
      const html = typeof res.data === 'string' ? res.data : '';
      const notFound = html.includes('The specified profile could not be found') || res.status === 404;
      const exists = res.status === 200 && !notFound;
      return {
        platform: platform.name,
        category: platform.category,
        icon: platform.icon,
        logoSlug,
        iconUrl,
        url: profileUrl,
        exists,
        status: exists ? 'FOUND' : 'NOT_FOUND',
        statusCode: res.status,
        responseTimeMs: Date.now() - startTime,
      };
    }

    // Default status code check
    const res = await client.get(checkUrl);
    const exists = res.status === 200;
    return {
      platform: platform.name,
      category: platform.category,
      icon: platform.icon,
      logoSlug,
      iconUrl,
      url: profileUrl,
      exists,
      status: exists ? 'FOUND' : (res.status === 404 ? 'NOT_FOUND' : 'UNKNOWN'),
      statusCode: res.status,
      responseTimeMs: Date.now() - startTime,
    };
  } catch (err) {
    return {
      platform: platform.name,
      category: platform.category,
      icon: platform.icon,
      logoSlug,
      iconUrl,
      url: profileUrl,
      exists: false,
      status: 'TIMEOUT',
      statusCode: 0,
      responseTimeMs: Date.now() - startTime,
    };
  }
}

export async function runSherlockScan(username) {
  if (!username || typeof username !== 'string') {
    throw new Error('Username is required');
  }

  const cleanUser = username.trim().replace(/^@/, '');
  if (!cleanUser || cleanUser.length < 2) {
    throw new Error('Valid username of at least 2 characters is required');
  }

  // Controlled concurrency batching: Check in chunks of 8 to prevent socket exhaustion and IP bans
  const BATCH_SIZE = 8;
  const results = [];

  for (let i = 0; i < PLATFORMS.length; i += BATCH_SIZE) {
    const chunk = PLATFORMS.slice(i, i + BATCH_SIZE);
    const chunkSettled = await Promise.allSettled(
      chunk.map((plat) => checkSinglePlatform(plat, cleanUser))
    );

    chunkSettled.forEach((s, idx) => {
      if (s.status === 'fulfilled') {
        results.push(s.value);
      } else {
        const plat = chunk[idx];
        results.push({
          platform: plat.name,
          category: plat.category,
          icon: plat.icon,
          url: plat.url.replace(/\{u\}/g, cleanUser),
          exists: false,
          status: 'ERROR',
          statusCode: 500,
          responseTimeMs: 0,
        });
      }
    });
  }

  const foundCount = results.filter((r) => r.exists).length;
  const totalCount = results.length;

  return {
    username: cleanUser,
    totalScanned: totalCount,
    totalFound: foundCount,
    scanTimestamp: new Date().toISOString(),
    results,
  };
}
