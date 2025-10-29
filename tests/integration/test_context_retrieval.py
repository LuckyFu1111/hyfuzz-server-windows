from src.knowledge.context_retrieval_layer import ContextRetrievalLayer

def test_context_retrieval_response():
    layer = ContextRetrievalLayer(vector_db=True, graph_db=True)
    result = layer.retrieve("overflow")
    assert result["graph"] is True
