export type State =
  | "draft" | "scope_validated" | "planned" | "approved" | "executing"
  | "verifying" | "triage" | "reported" | "halted" | "closed";

/** Ciclo obligatorio: Setup → Alcance → Planificación → Aprobación → Ejecución → Verificación → Triaje → Reporte. */
const NEXT: Record<State, State[]> = {
  draft: ["scope_validated", "halted"],
  scope_validated: ["planned", "halted"],
  planned: ["approved", "scope_validated", "halted"],
  approved: ["executing", "halted"],
  executing: ["verifying", "halted"],
  verifying: ["triage", "executing", "halted"],
  triage: ["reported", "verifying", "halted"],
  reported: ["closed"],
  halted: ["closed"],     // reactivar exige una NUEVA versión de la autorización
  closed: [],
};

export const canTransition = (from: State, to: State) => NEXT[from].includes(to);

/** Estados en los que se permite ejecutar módulos. */
export const EXECUTABLE_STATES: State[] = ["approved", "executing"];
