using 'main.bicep'

param prefix = 'lab'

// Round 1: Warn + Privileged   (observe)
// Round 2: Enforce + Privileged (block and mutate)
// Round 3: Enforce + Baseline   (add Pod Security Standards)
// Round 4: Enforce + Restricted (the target state for most app namespaces)
param safeguardsLevel = 'Warn'
param podSecurityStandardsLevel = 'Privileged'
param excludedNamespaces = ['lab-legacy']
