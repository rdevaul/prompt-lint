# Research Notes — Transformer Attention Mechanisms

## Overview
Self-attention allows each token to attend to all other tokens in the sequence.
The attention weight between tokens i and j is computed as softmax(QK^T / sqrt(d_k)).

## Key findings from the literature
- Vaswani et al. (2017) showed that multi-head attention outperforms single-head
- Later work (Clark et al. 2019) found specific heads capture syntactic relationships
- Positional encodings remain an active research area

## Open questions
1. How does attention scale to very long sequences?
2. What is the relationship between attention patterns and model interpretability?

## Next steps
Run ablation studies on head pruning to identify redundant attention heads.
