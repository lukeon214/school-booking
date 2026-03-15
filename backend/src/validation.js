const { z } = require('zod');

const QUESTION_TYPES = [
  'short_text', 'long_text', 'number', 'date', 'time',
  'email', 'phone', 'url', 'rating', 'yes_no',
  'radio', 'checkbox', 'select', 'grid',
];

const questionSchema = z.object({
  id:              z.string(),
  type:            z.enum(QUESTION_TYPES),
  label:           z.string(),
  description:     z.string().optional(),
  required:        z.boolean().optional().default(false),
  options:         z.array(z.string()).optional(),
  rows:            z.array(z.any()).optional(),
  columns:         z.array(z.any()).optional(),
  cells:           z.record(z.any()).optional(),
  singlePerRow:    z.boolean().optional(),
  singlePerColumn: z.boolean().optional(),
}).passthrough();

const formSchemaJson = z.object({
  questions: z.array(questionSchema),
});

function validateSchemaJson(value) {
  const result = formSchemaJson.safeParse(value);
  if (result.success) return { ok: true };
  const details = result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
  return { ok: false, details };
}

module.exports = { formSchemaJson, validateSchemaJson };
