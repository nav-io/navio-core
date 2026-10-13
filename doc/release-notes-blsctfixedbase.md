## Updated settings

- `-blsctfixedbase` now appears in `-help`, not only in `-help-debug`. The
  precomputed tables it controls are on by default; `-blsctfixedbase=0` verifies
  every range proof with the generic multi-scalar multiplication instead, at
  some verification speed, to free the tables' memory or rule them out when
  debugging.
