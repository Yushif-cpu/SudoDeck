'use client';

import React, { useState, useRef, useCallback } from 'react';

export interface GpsCoordinates {
  latitude: number;
  longitude: number;
  altitude?: number;
}

export interface ImageMetadata {
  fileName: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  fileType: string;
  dimensions?: { width: number; height: number };
  make?: string;
  model?: string;
  dateTime?: string;
  exposureTime?: string;
  fNumber?: string;
  iso?: string;
  focalLength?: string;
  software?: string;
  lensModel?: string;
  gps?: GpsCoordinates;
}

export interface OcrResult {
  rawText: string;
  confidence: number;
  detectedLandmarks: string[];
}

export interface AnalysisState {
  status: 'idle' | 'reading-exif' | 'running-ocr' | 'completed' | 'error';
  progressMessage: string;
  ocrProgress: number;
  error?: string;
}

// Landmark patterns for common Azerbaijani, Caucasian, European and International signs & stores
const KNOWN_STORE_PATTERNS = [
  /\b(Bravo|Bazarstore|Araz|Grandmart|Neptun|Oba|Almarket|Rahat|Bolmart|Spar|Carrefour)\b/gi,
  /\b(Aptek|Pharmacy|Apotheke|Eczane|Zeferan|Zeytun|Kanun)\b/gi,
  /\b(Baku|Ganja|Sumqayit|Quba|Sheki|Lankaran|Shusha|Khankendi|Yasamal|Nasimi|Sabayil|Narimanov)\b/gi,
  /\b(Kuc|Kucesi|Küç|Küçəsi|Pr|Prospekti|Prospekt|Street|St|Ave|Avenue|Road|Rd|Bulvar|Boulevard)\b/gi,
  /\b(Bank|Kapital|Pasha|ABB|UniBank|AccessBank|ExpressBank|Yelo|Rabitabank|ATM)\b/gi,
  /\b(Metro|Stansiya|Vagzal|Airport|Aeroport|Terminal)\b/gi,
  /\b(Hotel|Resort|Plaza|Mall|Center|Centre|Restoran|Restaurant|Cafe|Coffee)\b/gi,
  /\b(SOCAR|Azpetrol|Lukoil|BP|Total|Shell)\b/gi,
];

export default function VisualRecon() {
  const [imageSrc, setImageSrc] = useState<string | null>(null);
  const [metadata, setMetadata] = useState<ImageMetadata | null>(null);
  const [ocrResult, setOcrResult] = useState<OcrResult | null>(null);
  const [analysisState, setAnalysisState] = useState<AnalysisState>({
    status: 'idle',
    progressMessage: '',
    ocrProgress: 0,
  });
  const [copiedCoords, setCopiedCoords] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Helper to format byte sizes
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Helper to extract known landmarks and high-value proper nouns from raw OCR text
  const extractLandmarks = (text: string): string[] => {
    const landmarks = new Set<string>();

    KNOWN_STORE_PATTERNS.forEach((pattern) => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach((m) => landmarks.add(m.trim()));
      }
    });

    // Also extract consecutive capitalized words (potential shop/sign names)
    const capitalizedMatches = text.match(/\b[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{2,}(?:\s+[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{2,})*\b/g);
    if (capitalizedMatches) {
      capitalizedMatches.forEach((word) => {
        const clean = word.trim();
        if (clean.length > 3 && !['This', 'With', 'From', 'Have', 'They', 'Date'].includes(clean)) {
          landmarks.add(clean);
        }
      });
    }

    return Array.from(landmarks).slice(0, 12);
  };

  // Process selected file
  const processImageFile = async (file: File) => {
    if (!file.type.startsWith('image/')) {
      setAnalysisState({
        status: 'error',
        progressMessage: '',
        ocrProgress: 0,
        error: 'Zəhmət olmasa düzgün şəkil formatı seçin (JPEG, PNG, WEBP, TIFF, HEIC).',
      });
      return;
    }

    // Reset previous state
    setMetadata(null);
    setOcrResult(null);
    setAnalysisState({
      status: 'reading-exif',
      progressMessage: 'Şəkil daxilindəki EXIF və GPS koordinatları oxunur...',
      ocrProgress: 0,
    });

    // Generate local preview URL
    const objectUrl = URL.createObjectURL(file);
    setImageSrc(objectUrl);

    // Initial basic metadata
    const baseMeta: ImageMetadata = {
      fileName: file.name,
      fileSizeBytes: file.size,
      fileSizeFormatted: formatBytes(file.size),
      fileType: file.type,
    };

    // 1. Read EXIF & GPS
    let parsedGps: GpsCoordinates | undefined;
    try {
      // Dynamic import of exifr to guarantee client-side compatibility
      const exifrMod: any = await import('exifr');
      const exifr = exifrMod.default || exifrMod;

      // Extract full EXIF and GPS
      const exifData = await exifr.parse(file, {
        tiff: true,
        xmp: true,
        icc: false,
        jfif: true,
        ihdr: true,
        gps: true,
      });

      if (exifData) {
        baseMeta.make = exifData.Make || exifData.make;
        baseMeta.model = exifData.Model || exifData.model;
        baseMeta.software = exifData.Software || exifData.software;
        baseMeta.lensModel = exifData.LensModel || exifData.lensModel;

        if (exifData.DateTimeOriginal) {
          baseMeta.dateTime = new Date(exifData.DateTimeOriginal).toLocaleString();
        } else if (exifData.CreateDate) {
          baseMeta.dateTime = new Date(exifData.CreateDate).toLocaleString();
        }

        if (exifData.ExposureTime) {
          baseMeta.exposureTime = `1/${Math.round(1 / exifData.ExposureTime)}s (${exifData.ExposureTime}s)`;
        }
        if (exifData.FNumber) {
          baseMeta.fNumber = `f/${exifData.FNumber}`;
        }
        if (exifData.ISO) {
          baseMeta.iso = `ISO ${exifData.ISO}`;
        }
        if (exifData.FocalLength) {
          baseMeta.focalLength = `${exifData.FocalLength} mm`;
        }
        if (exifData.ExifImageWidth && exifData.ExifImageHeight) {
          baseMeta.dimensions = {
            width: exifData.ExifImageWidth,
            height: exifData.ExifImageHeight,
          };
        }
      }

      // Check explicit GPS location
      const gpsData = await exifr.gps(file);
      if (gpsData && typeof gpsData.latitude === 'number' && typeof gpsData.longitude === 'number') {
        parsedGps = {
          latitude: Number(gpsData.latitude.toFixed(6)),
          longitude: Number(gpsData.longitude.toFixed(6)),
        };
        baseMeta.gps = parsedGps;
      }
    } catch (exifErr: any) {
      console.warn('EXIF parsing notice:', exifErr?.message || exifErr);
    }

    // Measure intrinsic image dimensions if not yet obtained
    try {
      const img = new Image();
      img.src = objectUrl;
      await new Promise((resolve) => {
        img.onload = () => {
          if (!baseMeta.dimensions) {
            baseMeta.dimensions = { width: img.naturalWidth, height: img.naturalHeight };
          }
          resolve(true);
        };
        img.onerror = () => resolve(false);
      });
    } catch (_) {}

    setMetadata({ ...baseMeta });

    // 2. OCR Text Extraction via tesseract.js
    setAnalysisState({
      status: 'running-ocr',
      progressMessage: 'Tesseract OCR mühərriki başladılır və şəkildəki mətnlər analiz edilir...',
      ocrProgress: 10,
    });

    try {
      const tesseractMod: any = await import('tesseract.js');
      const Tesseract = tesseractMod.default || tesseractMod;
      const recognizeResult = await Tesseract.recognize(file, 'eng+aze+rus', {
        logger: (m: any) => {
          if (m.status === 'recognizing text' && typeof m.progress === 'number') {
            setAnalysisState((prev) => ({
              ...prev,
              ocrProgress: Math.min(Math.round(m.progress * 100), 98),
              progressMessage: `Mətnlər, mağaza lövhələri və küçə adları oxunur: ${Math.round(m.progress * 100)}%`,
            }));
          }
        },
      });

      const rawText = recognizeResult.data?.text || '';
      const confidence = Math.round(recognizeResult.data?.confidence || 0);
      const landmarks = extractLandmarks(rawText);

      setOcrResult({
        rawText: rawText.trim(),
        confidence,
        detectedLandmarks: landmarks,
      });

      setAnalysisState({
        status: 'completed',
        progressMessage: 'Analiz uğurla tamamlandı.',
        ocrProgress: 100,
      });
    } catch (ocrErr: any) {
      console.error('OCR error:', ocrErr);
      setOcrResult({
        rawText: '',
        confidence: 0,
        detectedLandmarks: [],
      });
      setAnalysisState({
        status: 'completed',
        progressMessage: 'EXIF tamamlandı, lakin OCR zamanı xəta baş verdi: ' + (ocrErr?.message || 'Bilinməyən xəta'),
        ocrProgress: 100,
      });
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processImageFile(e.target.files[0]);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processImageFile(e.dataTransfer.files[0]);
    }
  }, []);

  const copyCoordinates = () => {
    if (metadata?.gps) {
      navigator.clipboard.writeText(`${metadata.gps.latitude}, ${metadata.gps.longitude}`);
      setCopiedCoords(true);
      setTimeout(() => setCopiedCoords(false), 2000);
    }
  };

  // Load sample image with EXIF simulation for instant demonstration
  const loadDemoSample = (type: 'gps' | 'storefront') => {
    if (type === 'gps') {
      // High-accuracy Baku coastal geolocation demo
      setImageSrc('https://images.unsplash.com/photo-1579546929518-9e396f3cc809?w=900&auto=format&fit=crop&q=80');
      setMetadata({
        fileName: 'target_recon_baku_boulevard.jpg',
        fileSizeBytes: 2457812,
        fileSizeFormatted: '2.34 MB',
        fileType: 'image/jpeg',
        dimensions: { width: 4032, height: 3024 },
        make: 'Apple',
        model: 'iPhone 15 Pro Max',
        dateTime: '2026-08-14 17:42:09',
        exposureTime: '1/1250s (0.0008s)',
        fNumber: 'f/1.78',
        iso: 'ISO 64',
        focalLength: '24 mm',
        software: 'iOS 18.2.1',
        gps: {
          latitude: 40.370556,
          longitude: 49.845833,
        },
      });
      setOcrResult({
        rawText: 'BAKU BOULEVARD SEASIDE NATIONAL PARK\nBazarstore Express\nDeniz Mall Entrance 2\nAZ1000 Baku Azerbaijan',
        confidence: 94,
        detectedLandmarks: ['Bazarstore', 'Deniz Mall', 'Baku', 'Boulevard'],
      });
      setAnalysisState({
        status: 'completed',
        progressMessage: 'Nümunə GPS & OCR analiz məlumatları yükləndi.',
        ocrProgress: 100,
      });
    } else {
      // Storefront & landmarks OCR demo
      setImageSrc('https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=900&auto=format&fit=crop&q=80');
      setMetadata({
        fileName: 'commercial_strip_recon_target.jpg',
        fileSizeBytes: 1823410,
        fileSizeFormatted: '1.74 MB',
        fileType: 'image/jpeg',
        dimensions: { width: 3840, height: 2160 },
        make: 'Samsung',
        model: 'Galaxy S24 Ultra',
        dateTime: '2026-09-02 12:15:33',
        exposureTime: '1/640s (0.0015s)',
        fNumber: 'f/1.7',
        iso: 'ISO 50',
        focalLength: '23 mm',
        software: 'OneUI 6.1',
      });
      setOcrResult({
        rawText: 'BRAVO HYPERMARKET\nZəfəran Aptek 24/7\nKapital Bank ATM 048\nFətəli Xan Xoyski Prospekti 14',
        confidence: 91,
        detectedLandmarks: ['Bravo', 'Zəfəran', 'Aptek', 'Kapital Bank', 'Xoyski Prospekti'],
      });
      setAnalysisState({
        status: 'completed',
        progressMessage: 'Nümunə mağaza və OCR lövhə analizi yükləndi.',
        ocrProgress: 100,
      });
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 font-sans text-slate-100">

      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
        <a href="/" className="text-slate-400 hover:text-emerald-400 transition-colors flex items-center gap-1">
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          <span>Hub</span>
        </a>
        <span className="text-slate-600">/</span>
        <span className="text-emerald-400 font-semibold uppercase tracking-wider">VISUAL RECON & IMAGE GEOLOCATION</span>
      </div>

      {/* Hero Header */}
      <div className="border-b border-slate-800/80 pb-6">
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 mb-2 tracking-wider uppercase">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          THREAT & RECON // GEO-IMINT TELEMETRY SUITE
        </div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <span>Visual Recon & Image Geolocation</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 uppercase">
                v2.8 IMINT
              </span>
            </h1>
            <p className="text-sm text-slate-400 mt-2 max-w-3xl leading-relaxed">
              Extract embedded GPS telemetry via client-side EXIF interrogation, recognize municipal signage & store names with Tesseract OCR, and launch targeted visual triangulation through Google Lens & Yandex.
            </p>
          </div>

          {/* Quick Demo Launchers */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => loadDemoSample('gps')}
              className="px-3 py-1.5 rounded-xl bg-surface-800 hover:bg-surface-750 border border-slate-700/80 text-xs font-mono font-medium text-emerald-300 hover:text-white transition-all flex items-center gap-1.5 shadow-sm"
            >
              <span>🛰️ Nümunə GPS</span>
            </button>
            <button
              type="button"
              onClick={() => loadDemoSample('storefront')}
              className="px-3 py-1.5 rounded-xl bg-surface-800 hover:bg-surface-750 border border-slate-700/80 text-xs font-mono font-medium text-amber-300 hover:text-white transition-all flex items-center gap-1.5 shadow-sm"
            >
              <span>🏪 Nümunə OCR</span>
            </button>
          </div>
        </div>
      </div>

      {/* Upload Zone & Drag & Drop Area */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative cursor-pointer rounded-2xl border-2 border-dashed p-8 transition-all duration-200 text-center ${
          isDragOver
            ? 'border-emerald-400 bg-emerald-500/10 scale-[1.005]'
            : 'border-slate-700/80 bg-surface-900/80 hover:border-emerald-500/50 hover:bg-surface-850'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleFileChange}
        />

        <div className="max-w-md mx-auto flex flex-col items-center justify-center space-y-3 pointer-events-none">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-2xl shadow-inner">
            📷
          </div>
          <div>
            <h3 className="text-base font-bold text-white">
              Şəkli bura sürükləyin və ya fayl seçin
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Dəstəklənən formatlar: JPEG, PNG, WEBP, TIFF, HEIC. Analiz tam olaraq brauzerdə aparılır (100% məxfi).
            </p>
          </div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-800 text-[11px] font-mono text-slate-300 border border-slate-700">
            <span>Client-Side exifr + Tesseract.js OCR</span>
          </div>
        </div>
      </div>

      {/* Progress & Live Processing HUD */}
      {analysisState.status !== 'idle' && (
        <div className="rounded-xl bg-surface-900 border border-slate-800 p-4 space-y-2.5 shadow-lg">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              {analysisState.status === 'completed' ? (
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              ) : analysisState.status === 'error' ? (
                <span className="w-2 h-2 rounded-full bg-rose-400"></span>
              ) : (
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
              )}
              <span className="text-slate-300">{analysisState.progressMessage}</span>
            </div>
            <span className="text-emerald-400 font-bold">{analysisState.ocrProgress}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                analysisState.status === 'error'
                  ? 'bg-rose-500'
                  : analysisState.status === 'completed'
                  ? 'bg-emerald-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${analysisState.ocrProgress}%` }}
            ></div>
          </div>
          {analysisState.error && (
            <div className="text-xs text-rose-400 font-mono mt-1">
              Xəta: {analysisState.error}
            </div>
          )}
        </div>
      )}

      {/* Main Analysis Results Display */}
      {metadata && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* Left Column: Image Preview + Geolocation Map (5 Cols) */}
          <div className="lg:col-span-5 space-y-6">

            {/* Image Preview Card */}
            <div className="rounded-2xl border border-slate-800 bg-surface-900 overflow-hidden shadow-xl">
              <div className="px-4 py-3 bg-surface-850 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-slate-300 truncate max-w-[260px]">
                  {metadata.fileName}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-800 text-slate-400 border border-slate-700">
                  {metadata.fileSizeFormatted}
                </span>
              </div>
              <div className="relative aspect-video bg-[#050811] flex items-center justify-center overflow-hidden">
                {imageSrc && (
                  <img
                    src={imageSrc}
                    alt="Target Recon"
                    className="max-h-full max-w-full object-contain"
                  />
                )}
              </div>
            </div>

            {/* GPS Geolocation Panel */}
            <div className="rounded-2xl border border-slate-800 bg-surface-900 p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🛰️</span>
                  <div>
                    <h3 className="text-sm font-bold text-white">Geospatial Telemetry</h3>
                    <p className="text-[11px] text-slate-400">EXIF GPS sensor readout</p>
                  </div>
                </div>

                {metadata.gps ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    GPS LOCKED
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                    NO EMBEDDED GPS
                  </span>
                )}
              </div>

              {metadata.gps ? (
                <div className="space-y-4">
                  {/* Coordinates Badges */}
                  <div className="p-3 rounded-xl bg-surface-850 border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Coordinates (WGS84)</div>
                      <div className="text-xs font-mono font-bold text-emerald-400 mt-0.5">
                        {metadata.gps.latitude.toFixed(6)}, {metadata.gps.longitude.toFixed(6)}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={copyCoordinates}
                      className="px-2.5 py-1 rounded-lg bg-surface-800 hover:bg-surface-750 text-[11px] font-mono text-slate-300 hover:text-white border border-slate-700 transition-colors"
                    >
                      {copiedCoords ? '✓ Kopyalandı' : 'Kopyala'}
                    </button>
                  </div>

                  {/* Primary Button: Open in Google Maps */}
                  <a
                    href={`https://www.google.com/maps?q=${metadata.gps.latitude},${metadata.gps.longitude}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold font-mono tracking-wide shadow-lg shadow-emerald-950/40 transition-all flex items-center justify-center gap-2 group"
                  >
                    <span>Google Maps-də Aç</span>
                    <span className="group-hover:translate-x-0.5 transition-transform">↗</span>
                  </a>

                  {/* Interactive Map Embed */}
                  <div className="rounded-xl overflow-hidden border border-slate-800 h-52 bg-slate-950 relative">
                    <iframe
                      title="OpenStreetMap Recon View"
                      width="100%"
                      height="100%"
                      frameBorder="0"
                      scrolling="no"
                      marginHeight={0}
                      marginWidth={0}
                      src={`https://www.openstreetmap.org/export/embed.html?bbox=${metadata.gps.longitude - 0.008}%2C${metadata.gps.latitude - 0.005}%2C${metadata.gps.longitude + 0.008}%2C${metadata.gps.latitude + 0.005}&layer=mapnik&marker=${metadata.gps.latitude}%2C${metadata.gps.longitude}`}
                    ></iframe>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-slate-300 space-y-2">
                  <p>
                    Bu şəkildə daxili GPS koordinatları aşkar edilmədi. Şəkil çəkilərkən yerləşmə xidməti deaktiv ola bilər və ya sosial şəbəkə tərəfindən metadata təmizlənmişdir.
                  </p>
                  <p className="text-amber-400 font-semibold">
                    💡 Məkanı təyin etmək üçün sağ tərəfdəki OCR mətnlərindən və Google Lens / Yandex vizual axtarış düymələrindən istifadə edin.
                  </p>
                </div>
              )}
            </div>

            {/* Reverse Visual Search Launchers */}
            <div className="rounded-2xl border border-slate-800 bg-surface-900 p-5 space-y-3 shadow-xl">
              <div className="flex items-center gap-2">
                <span className="text-lg">🔎</span>
                <div>
                  <h3 className="text-sm font-bold text-white">Vizual Axtarış İstiqamətləri</h3>
                  <p className="text-[11px] text-slate-400">Təsviri axtarış sistemlərində yoxlayın</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2.5 pt-1">
                <a
                  href="https://lens.google.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-3 rounded-xl bg-surface-850 hover:bg-surface-800 border border-slate-700/80 hover:border-blue-500/50 text-xs font-semibold text-slate-200 hover:text-white transition-all flex items-center justify-between group"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-blue-400 font-bold">G</span>
                    <span>Google Lens</span>
                  </div>
                  <span className="text-slate-500 group-hover:text-blue-400 transition-colors">↗</span>
                </a>

                <a
                  href="https://yandex.com/images/search?rpt=imageview"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-3 rounded-xl bg-surface-850 hover:bg-surface-800 border border-slate-700/80 hover:border-rose-500/50 text-xs font-semibold text-slate-200 hover:text-white transition-all flex items-center justify-between group"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-rose-400 font-bold">Y</span>
                    <span>Yandex Visual</span>
                  </div>
                  <span className="text-slate-500 group-hover:text-rose-400 transition-colors">↗</span>
                </a>
              </div>
            </div>

          </div>

          {/* Right Column: OCR Landmarks & EXIF Metadata Table (7 Cols) */}
          <div className="lg:col-span-7 space-y-6">

            {/* OCR & Landmark Recognition Section */}
            <div className="rounded-2xl border border-slate-800 bg-surface-900 p-5 sm:p-6 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span className="text-xl">🏪</span>
                  <div>
                    <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                      <span>Detected Text / Landmarks</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                        OCR ENGINE
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400">
                      Mağaza adları, yol nişanları, lövhələr və obyekt yazıları
                    </p>
                  </div>
                </div>

                {ocrResult && (
                  <span className="text-[11px] font-mono text-slate-400">
                    Dəqiqlik: <strong className="text-emerald-400">{ocrResult.confidence}%</strong>
                  </span>
                )}
              </div>

              {/* Identified Landmarks Tags */}
              {ocrResult && ocrResult.detectedLandmarks.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-400">
                    Aşkar Olunan Landmarker & Şəbəkələr:
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {ocrResult.detectedLandmarks.map((landmark, idx) => (
                      <a
                        key={idx}
                        href={`https://www.google.com/search?q=${encodeURIComponent(landmark + ' Baku')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-xs font-mono font-medium text-amber-300 hover:text-amber-200 transition-colors shadow-sm"
                      >
                        <span>📍 {landmark}</span>
                        <span className="text-[10px] text-amber-400/60">↗</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw OCR Text Terminal */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>Tam Çıxarılan Mətn (Raw Output):</span>
                  {ocrResult?.rawText && (
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(ocrResult.rawText)}
                      className="text-emerald-400 hover:text-emerald-300 text-[11px] underline"
                    >
                      Mətni Kopyala
                    </button>
                  )}
                </div>
                <div className="rounded-xl bg-[#060913] border border-slate-800/90 p-4 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                  {ocrResult?.rawText ? (
                    ocrResult.rawText
                  ) : (
                    <span className="text-slate-600 italic">
                      Şəkildə oxuna bilən aydın mətn və ya mağaza lövhəsi tapılmadı.
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Technical EXIF Metadata Table */}
            <div className="rounded-2xl border border-slate-800 bg-surface-900 overflow-hidden shadow-xl">
              <div className="px-5 py-3.5 bg-surface-850 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-base">📊</span>
                  <h3 className="text-xs sm:text-sm font-bold text-white uppercase tracking-wider font-mono">
                    Şəkil Metadata & Optik Göstəricilər
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-slate-400">
                  EXIF 2.32 SPEC
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <tbody>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold w-1/3">Kamera İstehsalçısı (Make)</td>
                      <td className="py-2.5 px-4 text-white font-medium">{metadata.make || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Kamera Modeli (Model)</td>
                      <td className="py-2.5 px-4 text-emerald-400 font-bold">{metadata.model || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Çəkiliş Tarixi (DateTime)</td>
                      <td className="py-2.5 px-4 text-cyan-300 font-medium">{metadata.dateTime || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Ölçü (Dimensions)</td>
                      <td className="py-2.5 px-4 text-white">
                        {metadata.dimensions ? `${metadata.dimensions.width} × ${metadata.dimensions.height} px` : 'Məlumat yoxdur'}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Fayl Həcmi & Tipi</td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {metadata.fileSizeFormatted} ({metadata.fileType})
                      </td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Ekspozisiya (Shutter Speed)</td>
                      <td className="py-2.5 px-4 text-slate-300">{metadata.exposureTime || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Diafraqma (F-Number)</td>
                      <td className="py-2.5 px-4 text-slate-300">{metadata.fNumber || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">İSO Həssaslığı (ISO)</td>
                      <td className="py-2.5 px-4 text-slate-300">{metadata.iso || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Fokus Məsafəsi</td>
                      <td className="py-2.5 px-4 text-slate-300">{metadata.focalLength || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="hover:bg-surface-850/50 transition-colors">
                      <td className="py-2.5 px-4 text-slate-400 font-semibold">Proqram Təminatı (OS/Soft)</td>
                      <td className="py-2.5 px-4 text-slate-300">{metadata.software || 'Standart Firmware'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
