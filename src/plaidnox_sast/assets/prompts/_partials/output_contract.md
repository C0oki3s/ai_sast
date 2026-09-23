## Output contract

Reply with exactly one JSON object and nothing else: no Markdown, no headings, no code fences, and no prose before or after the object. The object must conform to the JSON Schema below. Use exactly the property names it defines, include every required property, and add no other properties. Record evidence gaps, uncertainty, and coverage limits inside the fields this schema provides; never answer with a narrative report instead of the object.

{{ output_schema | json }}
