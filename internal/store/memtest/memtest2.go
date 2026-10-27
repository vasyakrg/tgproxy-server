package memtest

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// ---- outbox ----

type outboxRepo struct{ s *Store }

func (r outboxRepo) find(id int64) int {
	return slices.IndexFunc(r.s.outbox, func(o store.OutboxItem) bool { return o.ID == id })
}

func (r outboxRepo) Enqueue(_ context.Context, it store.OutboxItem) (store.OutboxItem, error) {
	if err := it.Validate(); err != nil {
		return store.OutboxItem{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if it.CreatedAt.IsZero() {
		it.CreatedAt = time.Now()
	}
	it.CreatedAt = trunc(it.CreatedAt)
	r.s.outboxID++
	it.ID = r.s.outboxID
	it.SentAt, it.Attempts, it.LastError = nil, 0, ""
	r.s.outbox = append(r.s.outbox, it)
	return it, nil
}

func (r outboxRepo) Pending(_ context.Context, limit int) ([]store.OutboxItem, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []store.OutboxItem
	for _, o := range r.s.outbox {
		if o.SentAt == nil && len(out) < limit {
			out = append(out, o)
		}
	}
	return out, nil
}

func (r outboxRepo) Recent(_ context.Context, limit int) ([]store.OutboxItem, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []store.OutboxItem
	for i := len(r.s.outbox) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, r.s.outbox[i])
	}
	return out, nil
}

func (r outboxRepo) CountPending(context.Context) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for _, o := range r.s.outbox {
		if o.SentAt == nil {
			n++
		}
	}
	return n, nil
}

func (r outboxRepo) LastByKey(_ context.Context, key string) (store.OutboxItem, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := len(r.s.outbox) - 1; i >= 0; i-- {
		if r.s.outbox[i].DedupKey == key {
			return r.s.outbox[i], nil
		}
	}
	return store.OutboxItem{}, store.ErrNotFound
}

func (r outboxRepo) MarkSent(_ context.Context, id int64, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.ErrNotFound
	}
	t := trunc(at)
	r.s.outbox[i].SentAt = &t
	r.s.outbox[i].Attempts++
	r.s.outbox[i].LastError = ""
	return nil
}

func (r outboxRepo) RecordAttempt(_ context.Context, id int64, lastError string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.ErrNotFound
	}
	r.s.outbox[i].Attempts++
	r.s.outbox[i].LastError = lastError
	return nil
}

func (r outboxRepo) DeleteSentBefore(_ context.Context, t time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	before := len(r.s.outbox)
	r.s.outbox = slices.DeleteFunc(r.s.outbox, func(o store.OutboxItem) bool {
		return o.SentAt != nil && o.SentAt.Before(trunc(t))
	})
	return before - len(r.s.outbox), nil
}

// ---- history ----

type historyRepo struct{ s *Store }

func (r historyRepo) Append(_ context.Context, res store.Resolution, samples []store.Sample) error {
	m, ok := r.s.samples[res]
	if !ok {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, sm := range samples {
		sm.At = trunc(sm.At)
		sm.Buckets = slices.Clone(sm.Buckets)
		if len(sm.Buckets) == 0 {
			sm.Buckets = nil
		}
		sm.Denied = cloneDenied(sm.Denied)
		m[[2]string{sm.AgentID, sm.At.Format(time.RFC3339Nano)}] = sm
	}
	return nil
}

func (r historyRepo) Range(_ context.Context, res store.Resolution, agentID string, from, to time.Time) ([]store.Sample, error) {
	m, ok := r.s.samples[res]
	if !ok {
		return nil, store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.Sample
	for _, sm := range m {
		if sm.At.Before(trunc(from)) || !sm.At.Before(trunc(to)) {
			continue
		}
		if agentID != "" && sm.AgentID != agentID {
			continue
		}
		sm.Buckets = slices.Clone(sm.Buckets)
		sm.Denied = cloneDenied(sm.Denied)
		out = append(out, sm)
	}
	slices.SortFunc(out, func(a, b store.Sample) int {
		return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.AgentID, b.AgentID))
	})
	return out, nil
}

func (r historyRepo) Prune(_ context.Context, res store.Resolution, before time.Time) (int64, error) {
	m, ok := r.s.samples[res]
	if !ok {
		return 0, store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var n int64
	for k, sm := range m {
		if sm.At.Before(trunc(before)) {
			delete(m, k)
			n++
		}
	}
	return n, nil
}

func cloneDenied(m map[string]int64) map[string]int64 {
	if len(m) == 0 {
		return nil
	}
	return maps.Clone(m)
}

// ---- audit ----

type auditRepo struct{ s *Store }

func (r auditRepo) Append(_ context.Context, e store.AuditEntry) (store.AuditEntry, error) {
	if e.Actor == "" || e.Action == "" {
		return store.AuditEntry{}, store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = trunc(e.At)
	r.s.auditID++
	e.ID = r.s.auditID
	r.s.audit = append(r.s.audit, e)
	return e, nil
}

func (r auditRepo) List(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []store.AuditEntry
	for i := len(r.s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := r.s.audit[i]
		if (q.BeforeID > 0 && e.ID >= q.BeforeID) || (q.Actor != "" && e.Actor != q.Actor) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ---- host keys ----

type hostKeyRepo struct{ s *Store }

func (r hostKeyRepo) Get(_ context.Context, host string) (store.HostKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k, ok := r.s.hostKeys[host]
	if !ok {
		return store.HostKey{}, store.ErrNotFound
	}
	k.PublicKey = clone(k.PublicKey)
	return k, nil
}

func (r hostKeyRepo) Put(_ context.Context, k store.HostKey) error {
	if k.Host == "" || k.Fingerprint == "" || len(k.PublicKey) == 0 {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if cur, ok := r.s.hostKeys[k.Host]; ok {
		k.CreatedAt = cur.CreatedAt // как ON CONFLICT в SQLite: created_at сохраняется
	} else if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	k.CreatedAt = trunc(k.CreatedAt)
	k.PublicKey = clone(k.PublicKey)
	r.s.hostKeys[k.Host] = k
	return nil
}

func (r hostKeyRepo) List(_ context.Context) ([]store.HostKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make([]store.HostKey, 0, len(r.s.hostKeys))
	for _, k := range r.s.hostKeys {
		k.PublicKey = clone(k.PublicKey)
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func (r hostKeyRepo) Delete(_ context.Context, host string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.hostKeys[host]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.hostKeys, host)
	return nil
}

// ---- certs ----

type certRepo struct{ s *Store }

func (r certRepo) Put(_ context.Context, c store.CertRecord) error {
	if c.Serial == "" || c.AgentID == "" || len(c.CertPEM) == 0 {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.certs[c.Serial]; ok {
		return store.ErrConflict
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	c.NotBefore, c.NotAfter, c.CreatedAt = trunc(c.NotBefore), trunc(c.NotAfter), trunc(c.CreatedAt)
	c.CertPEM = clone(c.CertPEM)
	r.s.certs[c.Serial] = c
	return nil
}

func (r certRepo) Get(_ context.Context, serial string) (store.CertRecord, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.certs[serial]
	if !ok {
		return store.CertRecord{}, store.ErrNotFound
	}
	c.CertPEM = clone(c.CertPEM)
	return c, nil
}

func (r certRepo) filter(pred func(store.CertRecord) bool) []store.CertRecord {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.CertRecord
	for _, c := range r.s.certs {
		if pred(c) {
			c.CertPEM = clone(c.CertPEM)
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b store.CertRecord) int {
		return cmp.Or(a.NotAfter.Compare(b.NotAfter), cmp.Compare(a.Serial, b.Serial))
	})
	return out
}

func (r certRepo) ListByAgent(_ context.Context, agentID string) ([]store.CertRecord, error) {
	return r.filter(func(c store.CertRecord) bool { return c.AgentID == agentID }), nil
}

func (r certRepo) ListExpiring(_ context.Context, before time.Time) ([]store.CertRecord, error) {
	return r.filter(func(c store.CertRecord) bool { return c.NotAfter.Before(trunc(before)) }), nil
}

func (r certRepo) Deny(_ context.Context, d store.DeniedCert) error {
	if d.Serial == "" {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.denied[d.Serial]; ok {
		return nil
	}
	if d.DeniedAt.IsZero() {
		d.DeniedAt = time.Now()
	}
	d.NotAfter, d.DeniedAt = trunc(d.NotAfter), trunc(d.DeniedAt)
	r.s.denied[d.Serial] = d
	return nil
}

func (r certRepo) IsDenied(_ context.Context, serial string) (bool, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	_, ok := r.s.denied[serial]
	return ok, nil
}

func (r certRepo) ListDenied(context.Context) ([]store.DeniedCert, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.DeniedCert
	for _, d := range r.s.denied {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b store.DeniedCert) int {
		return cmp.Or(a.DeniedAt.Compare(b.DeniedAt), cmp.Compare(a.Serial, b.Serial))
	})
	return out, nil
}

func (r certRepo) PruneDenied(_ context.Context, now time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, d := range r.s.denied {
		if d.NotAfter.Before(trunc(now)) {
			delete(r.s.denied, k)
			n++
		}
	}
	return n, nil
}

func (r certRepo) SaveCA(_ context.Context, ca store.CARecord) error {
	if len(ca.CertPEM) == 0 || len(ca.SealedKey) == 0 {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.s.ca != nil {
		return store.ErrConflict
	}
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = time.Now()
	}
	ca.CreatedAt = trunc(ca.CreatedAt)
	ca.CertPEM, ca.SealedKey = clone(ca.CertPEM), clone(ca.SealedKey)
	r.s.ca = &ca
	return nil
}

func (r certRepo) LoadCA(context.Context) (store.CARecord, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.s.ca == nil {
		return store.CARecord{}, store.ErrNotFound
	}
	ca := *r.s.ca
	ca.CertPEM, ca.SealedKey = clone(ca.CertPEM), clone(ca.SealedKey)
	return ca, nil
}

// ---- enrollments ----

type enrollRepo struct{ s *Store }

func (r enrollRepo) Create(_ context.Context, e store.Enrollment) error {
	if err := e.Validate(); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, x := range r.s.enrolls {
		if x.ID == e.ID || string(x.TokenHash) == string(e.TokenHash) {
			return store.ErrConflict
		}
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	e.CreatedAt, e.ExpiresAt, e.UsedAt = trunc(e.CreatedAt), trunc(e.ExpiresAt), nil
	e.TokenHash = clone(e.TokenHash)
	r.s.enrolls[e.ID] = e
	return nil
}

func (r enrollRepo) Consume(_ context.Context, hash []byte, now time.Time) (store.Enrollment, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, e := range r.s.enrolls {
		if string(e.TokenHash) == string(hash) && e.UsedAt == nil && e.ExpiresAt.After(trunc(now)) {
			t := trunc(now)
			e.UsedAt = &t
			r.s.enrolls[id] = e
			e.TokenHash = clone(e.TokenHash)
			return e, nil
		}
	}
	return store.Enrollment{}, store.ErrNotFound
}

func (r enrollRepo) ListPending(_ context.Context, now time.Time) ([]store.Enrollment, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.Enrollment
	for _, e := range r.s.enrolls {
		if e.UsedAt == nil && e.ExpiresAt.After(trunc(now)) {
			e.TokenHash = clone(e.TokenHash)
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b store.Enrollment) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

func (r enrollRepo) Get(_ context.Context, id string) (store.Enrollment, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.enrolls[id]
	if !ok {
		return store.Enrollment{}, store.ErrNotFound
	}
	e.TokenHash = clone(e.TokenHash)
	return e, nil
}

func (r enrollRepo) Delete(_ context.Context, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.enrolls[id]
	if !ok || e.UsedAt != nil {
		return store.ErrNotFound
	}
	delete(r.s.enrolls, id)
	return nil
}

func (r enrollRepo) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for id, e := range r.s.enrolls {
		if !e.ExpiresAt.After(trunc(now)) {
			delete(r.s.enrolls, id)
			n++
		}
	}
	return n, nil
}

// ---- error events ----

type errRepo struct{ s *Store }

func (r errRepo) Append(_ context.Context, e store.ErrorEvent) (store.ErrorEvent, error) {
	if err := e.Validate(); err != nil {
		return store.ErrorEvent{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = trunc(e.At)
	r.s.errID++
	e.ID = r.s.errID
	r.s.errs = append(r.s.errs, e)
	return e, nil
}

func (r errRepo) List(_ context.Context, q store.ErrorQuery) ([]store.ErrorEvent, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []store.ErrorEvent
	for i := len(r.s.errs) - 1; i >= 0 && len(out) < limit; i-- {
		e := r.s.errs[i]
		switch {
		case q.BeforeID > 0 && e.ID >= q.BeforeID,
			q.AgentID != "" && e.AgentID != q.AgentID,
			q.BotID != "" && e.BotID != q.BotID,
			q.Method != "" && e.Method != q.Method,
			q.Outcome != "" && e.Outcome != q.Outcome,
			q.Phase != "" && e.Phase != q.Phase,
			q.Code != 0 && e.Code != q.Code,
			q.RequestID != "" && e.RequestID != q.RequestID,
			q.Reason != "" && e.Reason != q.Reason,
			q.ClientIP != "" && e.ClientIP != q.ClientIP:
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (r errRepo) Trim(_ context.Context, keep int, before time.Time) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n0 := len(r.s.errs)
	if keep > 0 && len(r.s.errs) > keep {
		r.s.errs = slices.Clone(r.s.errs[len(r.s.errs)-keep:])
	}
	if !before.IsZero() {
		r.s.errs = slices.DeleteFunc(r.s.errs, func(e store.ErrorEvent) bool { return e.At.Before(trunc(before)) })
	}
	return int64(n0 - len(r.s.errs)), nil
}

// ---- install jobs ----

type jobRepo struct{ s *Store }

func (r jobRepo) Create(_ context.Context, j store.InstallJob) error {
	if err := j.Validate(); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.jobs[j.ID]; ok {
		return store.ErrConflict
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now()
	}
	j.CreatedAt = trunc(j.CreatedAt)
	r.s.jobs[j.ID] = j
	return nil
}

func (r jobRepo) Get(_ context.Context, id string) (store.InstallJob, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	j, ok := r.s.jobs[id]
	if !ok {
		return store.InstallJob{}, store.ErrNotFound
	}
	return j, nil
}

func (r jobRepo) SetState(_ context.Context, id, state, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	j, ok := r.s.jobs[id]
	if !ok {
		return store.ErrNotFound
	}
	j.State, j.Error = state, errMsg
	if state != store.InstallRunning {
		t := nowMS()
		j.FinishedAt = &t
	} else {
		j.FinishedAt = nil
	}
	r.s.jobs[id] = j
	return nil
}

func (r jobRepo) SetAgent(_ context.Context, id, agentID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	j, ok := r.s.jobs[id]
	if !ok {
		return store.ErrNotFound
	}
	j.AgentID = agentID
	r.s.jobs[id] = j
	return nil
}

func (r jobRepo) AppendEvent(_ context.Context, e store.InstallJobEvent) (store.InstallJobEvent, error) {
	if err := e.Validate(); err != nil {
		return store.InstallJobEvent{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.jobs[e.JobID]; !ok {
		return store.InstallJobEvent{}, store.ErrConflict // FK как в SQLite
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = trunc(e.At)
	if e.Level == "" {
		e.Level = "info"
	}
	r.s.jobEvID++
	e.ID = r.s.jobEvID
	r.s.jobEvents = append(r.s.jobEvents, e)
	return e, nil
}

func (r jobRepo) Events(_ context.Context, jobID string, afterID int64) ([]store.InstallJobEvent, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.InstallJobEvent
	for _, e := range r.s.jobEvents {
		if e.JobID == jobID && e.ID > afterID {
			out = append(out, e)
		}
	}
	return out, nil
}

// ---- settings ----

type settingsRepo struct{ s *Store }

func (r settingsRepo) Get(_ context.Context, key string) (string, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	v, ok := r.s.settings[key]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (r settingsRepo) Set(_ context.Context, key, value string) error {
	if key == "" {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.settings[key] = value
	return nil
}

func (r settingsRepo) List(context.Context) (map[string]string, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return maps.Clone(r.s.settings), nil
}

// ---- rollouts ----

type rolloutRepo struct{ s *Store }

func (r rolloutRepo) Create(_ context.Context, o store.Rollout, steps []store.RolloutStep) error {
	if err := o.Validate(); err != nil {
		return err
	}
	for _, st := range steps {
		if err := st.Validate(); err != nil {
			return err
		}
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, ex := range r.s.rollouts {
		if ex.ID == o.ID || (o.Active() && ex.Active()) {
			return store.ErrConflict
		}
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now()
	}
	o.CreatedAt = trunc(o.CreatedAt)
	r.s.rollouts = append(r.s.rollouts, o)
	now := nowMS()
	seen := map[string]bool{}
	for _, st := range steps {
		if seen[st.AgentID] {
			return store.ErrConflict
		}
		seen[st.AgentID] = true
		st.RolloutID, st.UpdatedAt = o.ID, now
		r.s.rolloutSteps = append(r.s.rolloutSteps, st)
	}
	return nil
}

func (r rolloutRepo) find(id string) int {
	return slices.IndexFunc(r.s.rollouts, func(o store.Rollout) bool { return o.ID == id })
}

func (r rolloutRepo) Get(_ context.Context, id string) (store.Rollout, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.Rollout{}, store.ErrNotFound
	}
	return r.s.rollouts[i], nil
}

func (r rolloutRepo) Active(_ context.Context) (store.Rollout, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := len(r.s.rollouts) - 1; i >= 0; i-- {
		if r.s.rollouts[i].Active() {
			return r.s.rollouts[i], nil
		}
	}
	return store.Rollout{}, store.ErrNotFound
}

func (r rolloutRepo) Latest(_ context.Context) (store.Rollout, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if len(r.s.rollouts) == 0 {
		return store.Rollout{}, store.ErrNotFound
	}
	return r.s.rollouts[len(r.s.rollouts)-1], nil
}

func (r rolloutRepo) SetState(_ context.Context, id, state, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.ErrNotFound
	}
	o := r.s.rollouts[i]
	o.State, o.Error = state, errMsg
	if o.Active() {
		o.FinishedAt = nil
	} else {
		t := nowMS()
		o.FinishedAt = &t
	}
	r.s.rollouts[i] = o
	return nil
}

func (r rolloutRepo) Steps(_ context.Context, id string) ([]store.RolloutStep, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.RolloutStep
	for _, st := range r.s.rolloutSteps {
		if st.RolloutID == id {
			out = append(out, st)
		}
	}
	slices.SortStableFunc(out, func(a, b store.RolloutStep) int { return cmp.Compare(a.Seq, b.Seq) })
	return out, nil
}

func (r rolloutRepo) SetStep(_ context.Context, id, agentID, state, fromVersion, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i, st := range r.s.rolloutSteps {
		if st.RolloutID == id && st.AgentID == agentID {
			st.State, st.Error, st.UpdatedAt = state, errMsg, nowMS()
			if fromVersion != "" {
				st.FromVersion = fromVersion
			}
			r.s.rolloutSteps[i] = st
			return nil
		}
	}
	return store.ErrNotFound
}

// ---- bans ----

type banRepo struct{ s *Store }

func (r banRepo) find(p netip.Prefix) int {
	return slices.IndexFunc(r.s.bans, func(b store.Ban) bool { return b.Prefix == p })
}

func (r banRepo) Upsert(_ context.Context, b store.Ban) (store.Ban, error) {
	if err := b.Validate(); err != nil {
		return store.Ban{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	b.CreatedAt = trunc(b.CreatedAt)
	b.LastHitAt, b.Hits = b.CreatedAt, 0
	if b.ExpiresAt != nil {
		t := trunc(*b.ExpiresAt)
		b.ExpiresAt = &t
	}
	r.s.bansVer++
	if i := r.find(b.Prefix); i >= 0 {
		b.ID = r.s.bans[i].ID
		r.s.bans[i] = b
		return b, nil
	}
	r.s.banID++
	b.ID = r.s.banID
	r.s.bans = append(r.s.bans, b)
	return b, nil
}

func (r banRepo) Get(_ context.Context, id int64) (store.Ban, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, b := range r.s.bans {
		if b.ID == id {
			return b, nil
		}
	}
	return store.Ban{}, store.ErrNotFound
}

func (r banRepo) GetByPrefix(_ context.Context, p netip.Prefix) (store.Ban, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if i := r.find(p); i >= 0 {
		return r.s.bans[i], nil
	}
	return store.Ban{}, store.ErrNotFound
}

func (r banRepo) ListActive(_ context.Context, now time.Time) ([]store.Ban, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.Ban
	for _, b := range r.s.bans {
		if b.Active(trunc(now)) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b store.Ban) int { return cmp.Compare(b.ID, a.ID) })
	return out, nil
}

func (r banRepo) Delete(_ context.Context, id int64) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i, b := range r.s.bans {
		if b.ID == id {
			r.s.bans = slices.Delete(r.s.bans, i, i+1)
			r.s.bansVer++
			return nil
		}
	}
	return store.ErrNotFound
}

func (r banRepo) AddHits(_ context.Context, id, n int64, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.bans {
		if r.s.bans[i].ID == id && n > 0 {
			r.s.bans[i].Hits += n
			if t := trunc(at); t.After(r.s.bans[i].LastHitAt) {
				r.s.bans[i].LastHitAt = t
			}
		}
	}
	return nil
}

func (r banRepo) Prune(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n0 := len(r.s.bans)
	b := trunc(before)
	r.s.bans = slices.DeleteFunc(r.s.bans, func(x store.Ban) bool {
		return x.ExpiresAt != nil && x.ExpiresAt.Before(b) && x.LastHitAt.Before(b)
	})
	if d := n0 - len(r.s.bans); d > 0 {
		r.s.bansVer++
		return d, nil
	}
	return 0, nil
}

func (r banRepo) Version(_ context.Context) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.bansVer, nil
}
