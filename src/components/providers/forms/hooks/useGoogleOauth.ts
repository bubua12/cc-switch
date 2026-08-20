import { useManagedAuth } from "./useManagedAuth";

/** Google OAuth device-code / web authentication hook. */
export function useGoogleOauth() {
  return useManagedAuth("google_oauth");
}
