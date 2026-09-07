import * as SelectPrimitive from "@radix-ui/react-select";
import { useEffect, useRef, useState } from "react";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

interface SelectProps {
  "aria-label": string;
  options: readonly SelectOption[];
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  name?: string;
  disabled?: boolean;
  required?: boolean;
  placeholder?: string;
  className?: string;
}

// Encoding allows an empty-string option (e.g. All actions) alongside Radix's
// empty-string placeholder, without changing values submitted by the form.
const encode = (value: string) => `option:${value}`;

export function Select({ options, value, defaultValue, onValueChange, name, disabled, required, placeholder = "Select an option", className = "", "aria-label": label }: SelectProps) {
  const [internalValue, setInternalValue] = useState(defaultValue ?? "");
  const trigger = useRef<HTMLButtonElement>(null);
  const selectedValue = value ?? internalValue;
  const selected = options.find((option) => option.value === selectedValue);

  useEffect(() => {
    const form = trigger.current?.form;
    const reset = () => setInternalValue(defaultValue ?? "");
    form?.addEventListener("reset", reset);
    return () => form?.removeEventListener("reset", reset);
  }, [defaultValue]);

  return <SelectPrimitive.Root
    value={selected ? encode(selectedValue) : ""}
    onValueChange={(next) => {
      // The hidden form control can emit an empty value while async options
      // mount. Only an actual menu choice should update application state.
      if (!next.startsWith("option:")) return;
      const decoded = next.slice("option:".length);
      setInternalValue(decoded);
      onValueChange?.(decoded);
    }}
    disabled={disabled || options.length === 0}
    required={required ?? false}
  >
    {name ? <input type="hidden" name={name} value={selectedValue} disabled={disabled} /> : null}
    <SelectPrimitive.Trigger ref={trigger} className={`select-trigger ${className}`} aria-label={label}>
      <SelectPrimitive.Value placeholder={placeholder}>{selected?.label}</SelectPrimitive.Value>
      <SelectPrimitive.Icon className="select-chevron">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m7 10 5 5 5-5" /></svg>
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content className="select-content" position="popper" sideOffset={6} collisionPadding={12}>
        <SelectPrimitive.ScrollUpButton className="select-scroll" aria-hidden="true">⌃</SelectPrimitive.ScrollUpButton>
        <SelectPrimitive.Viewport className="select-viewport">
          {options.map((option) => <SelectPrimitive.Item className="select-option" key={option.value} value={encode(option.value)} disabled={option.disabled ?? false}>
            <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
            <SelectPrimitive.ItemIndicator className="select-check">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m5 12 4 4L19 6" /></svg>
            </SelectPrimitive.ItemIndicator>
          </SelectPrimitive.Item>)}
        </SelectPrimitive.Viewport>
        <SelectPrimitive.ScrollDownButton className="select-scroll" aria-hidden="true">⌄</SelectPrimitive.ScrollDownButton>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  </SelectPrimitive.Root>;
}
