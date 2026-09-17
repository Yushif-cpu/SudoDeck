import TrafficForm from '@/components/TrafficForm';

export const metadata = {
  title: 'Web Traffic & Audience Intel — SudoDeck Threat & Recon',
  description: 'Instant domain traffic analysis, global ranking, and audience metrics powered by Similarweb & Supabase caching.',
};

export default function TrafficPage() {
  return (
    <main className="min-h-screen bg-surface-900">
      <TrafficForm />
    </main>
  );
}
