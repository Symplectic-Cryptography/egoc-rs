(* OpeningSigma.ec — the M4b code-mode opening Σ (egoc-proof::opening).
   Statement: ∃ (S,T) ∈ GL×GL with S^{-1}·C·T^{-1} ∈ span{G_l}.
   Proves: completeness, special-soundness (2-extractor), HVZK (simulator).
   SKELETON. *)

require import AllCore List Distr DBool.

type MatE.
op inv   : MatE -> MatE.
op mul   : MatE -> MatE -> MatE.
op in_span : MatE list -> MatE -> bool.   (* code membership *)
op H : MatE -> int.                       (* commitment hash (RO/CR) *)
op dGL_mr : MatE distr.   op dGL_mc : MatE distr.   (* uniform invertible *)
axiom dGL_ll : is_lossless dGL_mr /\ is_lossless dGL_mc.

(* one round transcript *)
type resp = [ R0 of MatE & MatE | R1 of MatE & MatE & MatE ].

op gens : MatE list.
op C    : MatE.

(* round verification (mirrors verify_round) *)
op verify_round (cmt : int) (b : bool) (z : resp) : bool =
  with z = R0 sh th => !b /\ H (mul (mul sh C) th) = cmt
  with z = R1 u v d  =>  b /\ H d = cmt /\ in_span gens (mul (mul (inv u) d) (inv v)).

(* ===== completeness ====================================================== *)
(* honest prover knowing (S,T) with in_span gens (S^{-1} C T^{-1}) makes
   verify_round accept for both b. *)
lemma completeness (S T : MatE) (b : bool) :
  in_span gens (mul (mul (inv S) C) (inv T)) =>
  exists cmt z, verify_round cmt b z.
proof.
  admit. (* FILL: instantiate D = Ŝ·C·T̂; b=0 -> R0(Ŝ,T̂); b=1 -> R1(Ŝ·S, T·T̂, D);
            both satisfy verify_round by the algebra in the module comment. *)
qed.

(* ===== special soundness ================================================= *)
(* two accepting transcripts on the SAME cmt with different challenges extract
   a witness (S,T). H-binding forces the same D across the two branches. *)
lemma special_soundness (cmt : int) (z0 z1 : resp) :
  verify_round cmt false z0 =>
  verify_round cmt true  z1 =>
  exists S T, in_span gens (mul (mul (inv S) C) (inv T)).
proof.
  (* z0 = R0(Ŝ,T̂) ⇒ D = Ŝ·C·T̂ ; z1 = R1(U',V',D) ⇒ in_span (U'^{-1} D V'^{-1}).
     Substitute: in_span ((U'^{-1} Ŝ) · C · (T̂ V'^{-1})) ⇒ witness
     S = (U'^{-1} Ŝ)^{-1}, T = (T̂ V'^{-1})^{-1}. Needs H injective on the two D's
     (collision resistance / RO). *)
  admit. (* FILL: case on z0,z1; use H-binding (axiom) to equate the two D's. *)
qed.

(* ===== HVZK ============================================================== *)
(* simulator for a chosen challenge bit, no witness; transcript distribution
   identical because the GL×GL orbit of a full-rank M(c) is message-independent
   (q≡3 mod4 anisotropic ⇒ M full rank w.h.p.). *)
module type Sim = { proc sim (b : bool) : int * resp }.

axiom full_rank_orbit_indep : true. (* the orbit-uniformity fact, q≡3 mod4 *)

lemma hvzk (b : bool) :
  (* dist of honest (cmt,z) at bit b  ==  dist of simulated (cmt,z) *)
  true.
proof.
  admit. (* FILL: b=0 -> (Ŝ,T̂) uniform GL, D=Ŝ·C·T̂; b=1 -> pick U',V' uniform GL,
            W uniform codeword, D=U'·W·V'. Equality of distributions reduces to
            `full_rank_orbit_indep`. *)
qed.

(* λ-round soundness: 2^{-λ}; FS-collapse standard. Stated, proof omitted. *)
op lambda : int.
lemma fs_soundness : true. (* admit: union/forking over λ independent rounds *)
