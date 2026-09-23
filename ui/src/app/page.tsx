import { Hero } from "@/components/hero";
import { Controls } from "@/components/controls";
import { Cascade } from "@/components/cascade";
import { Verdict } from "@/components/verdict";
import { PinsCard } from "@/components/pins-card";
import { AllowlistCard } from "@/components/allowlist-card";
import { References } from "@/components/references";
import { TryIt } from "@/components/try-it";

export default function TrustPage() {
  return (
    <main className="mx-auto max-w-[860px] px-5 py-10 md:py-14">
      <Hero />
      <div className="flex flex-col gap-6">
        <Controls />
        <Cascade />
        <Verdict />
        <PinsCard />
        <AllowlistCard />
      </div>
      <TryIt />
      <References />
    </main>
  );
}
