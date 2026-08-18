# Documentación del Proyecto IPS-IDBS-ML

Documentación organizada según el modelo **Diátaxis** (cuatro necesidades del usuario).

| Necesidad | Dónde |
|---|---|
| **Tutorials** (aprender paso a paso) | [Guía de instalación](./guias/instalacion.md) |
| **How-to guides** (resolver tareas) | [Guía de uso](./guias/uso.md) · [Guía de entrenamiento](./guias/entrenamiento.md) |
| **Reference** (información técnica) | [README raíz](../README.md) · [ADRs](./adr/) · [ML](./ml/) |
| **Explanation** (cómo y por qué) | [Red UNIPAZ](./red/) · [Tesis](./tesis/) · [Académico](./academico/) |

## Estructura

```
docs/
├── README.md                  # Este índice
├── CHANGELOG.md               # Historial de cambios verificado
├── academico/                 # Documentos de la tesis (docx/pdf/xlsx/tex)
├── adr/                       # Registros de decisiones de arquitectura
│   ├── 0001-pipeline-datos-v5.md
│   ├── 0002-sqliguard-segunda-etapa.md
│   └── 0003-umbral-unificado-ml.md
├── guias/                     # Cómo hacer (How-to)
│   ├── instalacion.md
│   ├── uso.md
│   └── entrenamiento.md
├── ml/                        # Análisis ML (histórico y vigente)
│   ├── analisis-modelo-ids.md
│   └── viabilidad-datasets.md
├── red/                       # Topología y despliegue en UNIPAZ
│   └── arquitectura-red-unipaz.md
└── tesis/                     # Anteproyecto y capítulos académicos
    ├── capitulos-proyecto.md
    ├── documentacion-mejoras.md
    └── formato-ante-proyecto.md
```

> [!NOTE]
> Los archivos con banner "Documento histórico" describen fases anteriores (v2/v3).
> Verificar siempre contra `guias/` y `adr/` para el estado actual.
