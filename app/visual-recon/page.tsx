import VisualRecon from '@/components/VisualRecon';

export const metadata = {
  title: 'Visual Recon & Image Geolocation — SudoDeck OSINT',
  description: 'Client-side EXIF GPS Extraction, Tesseract OCR Store & Landmark Recognition, and Reverse Visual Search.',
};

export default function VisualReconPage() {
  return (
    <main className="min-h-screen bg-surface-900">
      <VisualRecon />
    </main>
  );
}
