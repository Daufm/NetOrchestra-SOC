export default function DetectionProfileSelector({ profiles, value, onChange, disabled = false }) {
  return (
    <label className="block text-sm">
      Detection profile
      <select
        className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2"
        disabled={disabled}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {profiles.length === 0 && <option value="">No profiles available</option>}
        {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}
      </select>
      {profiles.find((profile) => profile.id === value)?.description && (
        <span className="mt-1 block text-xs text-slate-500">{profiles.find((profile) => profile.id === value).description}</span>
      )}
    </label>
  );
}
