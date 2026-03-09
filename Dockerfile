FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN python -m spacy download en_core_web_lg

COPY . .

RUN mkdir -p logs && echo "[]" > logs/threats.json

EXPOSE 7860

CMD ["streamlit", "run", "app.py", \
     "--server.port=7860", \
     "--server.address=0.0.0.0"]
```

---

## Step 3 — Update requirements.txt

Open `requirements.txt` and replace everything with:
```
streamlit
litellm
groq
python-dotenv
presidio-analyzer
presidio-anonymizer
transformers==4.40.0
torch==2.2.0+cpu
loguru
scikit-learn
spacy